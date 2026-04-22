using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Distributed cache-backed authenticated session token store that encrypts cached token payloads with ASP.NET Core Data Protection.
/// </summary>
public sealed class DistributedDownstreamUserTokenStore(
    IDistributedCache distributedCache,
    IDataProtectionProvider dataProtectionProvider,
    IOptions<TokenCacheOptions> tokenCacheOptions,
    IOptions<ActiveOidcProviderOptions> activeProviderOptions,
    ILogger<DistributedDownstreamUserTokenStore> logger) : IDownstreamUserTokenStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private const string CachePayloadVersion = "v1";
    private readonly UserTokenCacheKeyContextAccessor cacheKeyContextAccessor = new(activeProviderOptions);
    private readonly IDataProtector protector = dataProtectionProvider.CreateProtector(
        "Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication.DistributedDownstreamUserTokenStore",
        CachePayloadVersion);

    /// <inheritdoc />
    public async Task<StoredOidcSessionTokenSet?> GetSessionTokenSetAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        var payload = await ReadAsync<ProtectedSessionTokenPayload>(BuildSessionCacheKey(user), cancellationToken);
        OidcTokenStoreLog.SessionTokenCacheRead(logger, payload is not null);
        return payload?.TokenSet;
    }

    /// <inheritdoc />
    public async Task StoreSessionTokenSetAsync(ClaimsPrincipal user, StoredOidcSessionTokenSet tokenSet, CancellationToken cancellationToken)
    {
        await WriteAsync(
            BuildSessionCacheKey(user),
            new ProtectedSessionTokenPayload
            {
                Version = CachePayloadVersion,
                TokenSet = tokenSet
            },
            tokenSet.ExpiresAtUtc,
            cancellationToken);
        OidcTokenStoreLog.SessionTokenCacheWrite(logger, "success");
    }

    /// <inheritdoc />
    public async Task<CachedDownstreamApiTokenEntry?> GetApiTokenAsync(
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> scopes,
        CancellationToken cancellationToken)
    {
        var payload = await ReadAsync<ProtectedDownstreamApiTokenPayload>(
            BuildApiTokenCacheKey(user, downstreamApiName, scopes),
            cancellationToken);
        OidcTokenStoreLog.ApiTokenCacheRead(logger, downstreamApiName, payload is not null);
        return payload?.TokenEntry;
    }

    /// <inheritdoc />
    public async Task StoreApiTokenAsync(
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> scopes,
        CachedDownstreamApiTokenEntry tokenEntry,
        CancellationToken cancellationToken)
    {
        var cacheKey = BuildApiTokenCacheKey(user, downstreamApiName, scopes);
        await WriteAsync(
            cacheKey,
            new ProtectedDownstreamApiTokenPayload
            {
                Version = CachePayloadVersion,
                TokenEntry = tokenEntry
            },
            tokenEntry.ExpiresAtUtc,
            cancellationToken);
        OidcTokenStoreLog.ApiTokenCacheWrite(logger, downstreamApiName, "success");

        var index = await GetIndexAsync(user, cancellationToken) ?? new HashSet<string>(StringComparer.Ordinal);
        index.Add(cacheKey);
        await WriteAsync(
            BuildApiTokenIndexCacheKey(user),
            new ProtectedApiTokenIndexPayload
            {
                Version = CachePayloadVersion,
                CacheKeys = index.ToArray()
            },
            DateTimeOffset.UtcNow.AddHours(12),
            cancellationToken);
    }

    /// <inheritdoc />
    public async Task RemoveAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        OidcTokenStoreLog.TokenStoreRemoveStarted(logger);
        var indexKey = BuildApiTokenIndexCacheKey(user);
        var index = await GetIndexAsync(user, cancellationToken);
        var removedApiTokens = 0;
        if (index is not null)
        {
            foreach (var apiTokenKey in index)
            {
                await distributedCache.RemoveAsync(apiTokenKey, cancellationToken);
                removedApiTokens++;
            }
        }

        await distributedCache.RemoveAsync(indexKey, cancellationToken);
        await distributedCache.RemoveAsync(BuildSessionCacheKey(user), cancellationToken);
        OidcTokenStoreLog.TokenStoreRemoveCompleted(logger, removedApiTokens);
    }

    private async Task<HashSet<string>?> GetIndexAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        var payload = await ReadAsync<ProtectedApiTokenIndexPayload>(BuildApiTokenIndexCacheKey(user), cancellationToken);
        return payload?.CacheKeys is null
            ? null
            : new HashSet<string>(payload.CacheKeys, StringComparer.Ordinal);
    }

    private async Task<TPayload?> ReadAsync<TPayload>(string cacheKey, CancellationToken cancellationToken)
        where TPayload : IProtectedCachePayload
    {
        var protectedPayload = await distributedCache.GetStringAsync(cacheKey, cancellationToken);
        if (string.IsNullOrWhiteSpace(protectedPayload))
        {
            return default;
        }

        try
        {
            var json = protector.Unprotect(protectedPayload);
            var payload = JsonSerializer.Deserialize<TPayload>(json, SerializerOptions);
            if (!string.Equals(payload?.Version, CachePayloadVersion, StringComparison.Ordinal))
            {
                return default;
            }

            return payload;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        {
            OidcTokenStoreLog.TokenStorePayloadInvalid(
                logger,
                ex,
                typeof(TPayload).Name,
                ex is CryptographicException ? "data-protection" : "json");
            return default;
        }
    }

    private async Task WriteAsync<TPayload>(
        string cacheKey,
        TPayload payload,
        DateTimeOffset expiresAtUtc,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(payload, SerializerOptions);
        var protectedPayload = protector.Protect(json);
        var ttl = expiresAtUtc > DateTimeOffset.UtcNow
            ? expiresAtUtc - DateTimeOffset.UtcNow + TimeSpan.FromHours(12)
            : TimeSpan.FromHours(12);

        await distributedCache.SetStringAsync(
            cacheKey,
            protectedPayload,
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = ttl
            },
            cancellationToken);
    }

    private string BuildSessionCacheKey(ClaimsPrincipal user)
    {
        var context = cacheKeyContextAccessor.GetRequiredContext(user);
        return $"{tokenCacheOptions.Value.CacheKeyPrefix}:session:{context.Provider}:{context.Issuer}:{context.SubjectId}:{context.SessionId}";
    }

    private string BuildApiTokenIndexCacheKey(ClaimsPrincipal user)
    {
        var context = cacheKeyContextAccessor.GetRequiredContext(user);
        return $"{tokenCacheOptions.Value.CacheKeyPrefix}:api-index:{context.Provider}:{context.Issuer}:{context.SubjectId}:{context.SessionId}";
    }

    private string BuildApiTokenCacheKey(ClaimsPrincipal user, string downstreamApiName, IReadOnlyCollection<string> scopes)
    {
        var context = cacheKeyContextAccessor.GetRequiredContext(user);
        var normalizedScopes = OidcScopeResolver.NormalizeScopes(scopes);
        var scopeFingerprint = ComputeScopeFingerprint(normalizedScopes);
        return $"{tokenCacheOptions.Value.CacheKeyPrefix}:api:{context.Provider}:{context.Issuer}:{context.SubjectId}:{context.SessionId}:{downstreamApiName}:{scopeFingerprint}";
    }

    private static string ComputeScopeFingerprint(IEnumerable<string> scopes)
    {
        var serializedScopes = string.Join(" ", OidcScopeResolver.NormalizeScopes(scopes));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(serializedScopes));
        return Convert.ToHexString(hash);
    }

    private interface IProtectedCachePayload
    {
        string Version { get; init; }
    }

    private sealed class ProtectedSessionTokenPayload : IProtectedCachePayload
    {
        public string Version { get; init; } = string.Empty;

        public StoredOidcSessionTokenSet TokenSet { get; init; } = null!;
    }

    private sealed class ProtectedDownstreamApiTokenPayload : IProtectedCachePayload
    {
        public string Version { get; init; } = string.Empty;

        public CachedDownstreamApiTokenEntry TokenEntry { get; init; } = null!;
    }

    private sealed class ProtectedApiTokenIndexPayload : IProtectedCachePayload
    {
        public string Version { get; init; } = string.Empty;

        public string[] CacheKeys { get; init; } = [];
    }
}
