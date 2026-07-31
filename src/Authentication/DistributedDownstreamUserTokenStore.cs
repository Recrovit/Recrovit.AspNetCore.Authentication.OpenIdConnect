using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Default distributed cache-backed authenticated session token store that encrypts a versioned session aggregate with ASP.NET Core Data Protection.
/// This implementation is suitable for single-instance deployments unless the host replaces it with a store that provides
/// cross-node atomic compare-and-swap guarantees.
/// </summary>
public sealed class DistributedDownstreamUserTokenStore : IDownstreamUserTokenStore, IOidcSessionStateStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private const string CachePayloadVersion = "v2";
    private readonly IDistributedCache distributedCache;
    private readonly IOptions<TokenCacheOptions> tokenCacheOptions;
    private readonly ILogger<DistributedDownstreamUserTokenStore> logger;
    private readonly TimeProvider timeProvider;
    private readonly ILocalOidcSessionCoordinator localSessionCoordinator;
    private readonly UserTokenCacheKeyContextAccessor cacheKeyContextAccessor;
    private readonly UserTokenCacheKeyProtector cacheKeyProtector;
    private readonly IDataProtector protector;

    /// <summary>
    /// Initializes a new instance of the <see cref="DistributedDownstreamUserTokenStore"/> class.
    /// </summary>
    public DistributedDownstreamUserTokenStore(
        IDistributedCache distributedCache,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<TokenCacheOptions> tokenCacheOptions,
        IOptions<ActiveOidcProviderOptions> activeProviderOptions,
        ILogger<DistributedDownstreamUserTokenStore> logger)
        : this(
            distributedCache,
            dataProtectionProvider,
            tokenCacheOptions,
            activeProviderOptions,
            logger,
            LocalOidcSessionCoordinatorRegistry.GetOrCreate(activeProviderOptions),
            TimeProvider.System)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DistributedDownstreamUserTokenStore"/> class.
    /// </summary>
    public DistributedDownstreamUserTokenStore(
        IDistributedCache distributedCache,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<TokenCacheOptions> tokenCacheOptions,
        IOptions<ActiveOidcProviderOptions> activeProviderOptions,
        ILogger<DistributedDownstreamUserTokenStore> logger,
        TimeProvider timeProvider)
        : this(
            distributedCache,
            dataProtectionProvider,
            tokenCacheOptions,
            activeProviderOptions,
            logger,
            LocalOidcSessionCoordinatorRegistry.GetOrCreate(activeProviderOptions),
            timeProvider)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DistributedDownstreamUserTokenStore"/> class.
    /// </summary>
    public DistributedDownstreamUserTokenStore(
        IDistributedCache distributedCache,
        IDataProtectionProvider dataProtectionProvider,
        IOptions<TokenCacheOptions> tokenCacheOptions,
        IOptions<ActiveOidcProviderOptions> activeProviderOptions,
        ILogger<DistributedDownstreamUserTokenStore> logger,
        ILocalOidcSessionCoordinator localSessionCoordinator,
        TimeProvider timeProvider)
    {
        this.distributedCache = distributedCache;
        this.tokenCacheOptions = tokenCacheOptions;
        this.logger = logger;
        this.timeProvider = timeProvider;
        this.localSessionCoordinator = localSessionCoordinator;
        cacheKeyContextAccessor = new UserTokenCacheKeyContextAccessor(activeProviderOptions);
        cacheKeyProtector = new UserTokenCacheKeyProtector(tokenCacheOptions);
        protector = dataProtectionProvider.CreateProtector(
            "Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication.DistributedDownstreamUserTokenStore",
            CachePayloadVersion);
    }

    /// <inheritdoc />
    public async Task<VersionedOidcSessionState?> GetSessionStateAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        await using var localSessionLock = await localSessionCoordinator.AcquireAsync(user, cancellationToken);
        return await GetSessionStateCoreAsync(user, cancellationToken);
    }

    /// <inheritdoc />
    public Task<VersionedOidcSessionState?> GetSessionStateAsync(
        ClaimsPrincipal user,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(localSessionLock);
        return GetSessionStateCoreAsync(user, cancellationToken);
    }

    private async Task<VersionedOidcSessionState?> GetSessionStateCoreAsync(
        ClaimsPrincipal user,
        CancellationToken cancellationToken)
    {
        var payload = await ReadAsync(BuildSessionCacheKey(user), cancellationToken);
        OidcTokenStoreLog.SessionTokenCacheRead(logger, payload is not null && payload.State.SessionTokens is not null);
        return payload is null
            ? null
            : new VersionedOidcSessionState(payload.ConcurrencyVersion, payload.State.Clone());
    }

    /// <inheritdoc />
    public async Task<bool> TryCompareAndSwapSessionStateAsync(
        ClaimsPrincipal user,
        string? expectedVersion,
        OidcSessionState newState,
        CancellationToken cancellationToken)
    {
        await using var localSessionLock = await localSessionCoordinator.AcquireAsync(user, cancellationToken);
        return await TryCompareAndSwapSessionStateCoreAsync(user, expectedVersion, newState, cancellationToken);
    }

    /// <inheritdoc />
    public Task<bool> TryCompareAndSwapSessionStateAsync(
        ClaimsPrincipal user,
        string? expectedVersion,
        OidcSessionState newState,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(localSessionLock);
        return TryCompareAndSwapSessionStateCoreAsync(user, expectedVersion, newState, cancellationToken);
    }

    private async Task<bool> TryCompareAndSwapSessionStateCoreAsync(
        ClaimsPrincipal user,
        string? expectedVersion,
        OidcSessionState newState,
        CancellationToken cancellationToken)
    {
        var cacheKey = BuildSessionCacheKey(user);
        var current = await ReadAsync(cacheKey, cancellationToken);
        if (current is null)
        {
            if (expectedVersion is not null)
            {
                return false;
            }
        }
        else if (!string.Equals(current.ConcurrencyVersion, expectedVersion, StringComparison.Ordinal))
        {
            return false;
        }

        await WriteAsync(
            cacheKey,
            new ProtectedSessionStatePayload
            {
                SchemaVersion = CachePayloadVersion,
                ConcurrencyVersion = Guid.NewGuid().ToString("n"),
                State = newState.Clone()
            },
            ComputeStateExpiration(newState),
            cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task DeleteSessionStateAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        await using var localSessionLock = await localSessionCoordinator.AcquireAsync(user, cancellationToken);
        await DeleteSessionStateCoreAsync(user, cancellationToken);
    }

    /// <inheritdoc />
    public Task DeleteSessionStateAsync(
        ClaimsPrincipal user,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(localSessionLock);
        return DeleteSessionStateCoreAsync(user, cancellationToken);
    }

    private Task DeleteSessionStateCoreAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
        => distributedCache.RemoveAsync(BuildSessionCacheKey(user), cancellationToken);

    /// <inheritdoc />
    public async Task<StoredOidcSessionTokenSet?> GetSessionTokenSetAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        await using var localSessionLock = await localSessionCoordinator.AcquireAsync(user, cancellationToken);
        var state = await GetSessionStateCoreAsync(user, cancellationToken);
        return state?.State.SessionTokens?.Clone();
    }

    /// <inheritdoc />
    public async Task StoreSessionTokenSetAsync(ClaimsPrincipal user, StoredOidcSessionTokenSet tokenSet, CancellationToken cancellationToken)
    {
        await using var localSessionLock = await localSessionCoordinator.AcquireAsync(user, cancellationToken);
        await StoreSessionTokenSetCoreAsync(user, tokenSet, cancellationToken);
    }

    /// <inheritdoc />
    public Task StoreSessionTokenSetAsync(
        ClaimsPrincipal user,
        StoredOidcSessionTokenSet tokenSet,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(localSessionLock);
        return StoreSessionTokenSetCoreAsync(user, tokenSet, cancellationToken);
    }

    private async Task StoreSessionTokenSetCoreAsync(
        ClaimsPrincipal user,
        StoredOidcSessionTokenSet tokenSet,
        CancellationToken cancellationToken)
    {
        await UpdateStateCoreAsync(
            user,
            state =>
            {
                var next = state.Clone();
                next.SessionTokens = tokenSet.Clone();
                return next;
            },
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
        await using var localSessionLock = await localSessionCoordinator.AcquireAsync(user, cancellationToken);
        var state = await GetSessionStateCoreAsync(user, cancellationToken);
        var lookupKey = OidcSessionStateApiKey.Create(downstreamApiName, scopes);
        var entry = state is not null && state.State.ApiTokens.TryGetValue(lookupKey, out var tokenEntry)
            ? tokenEntry.Clone()
            : null;
        OidcTokenStoreLog.ApiTokenCacheRead(logger, downstreamApiName, entry is not null);
        return entry;
    }

    /// <inheritdoc />
    public async Task StoreApiTokenAsync(
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> scopes,
        CachedDownstreamApiTokenEntry tokenEntry,
        CancellationToken cancellationToken)
    {
        await using var localSessionLock = await localSessionCoordinator.AcquireAsync(user, cancellationToken);
        await StoreApiTokenCoreAsync(user, downstreamApiName, scopes, tokenEntry, cancellationToken);
    }

    /// <inheritdoc />
    public Task StoreApiTokenAsync(
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> scopes,
        CachedDownstreamApiTokenEntry tokenEntry,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(localSessionLock);
        return StoreApiTokenCoreAsync(user, downstreamApiName, scopes, tokenEntry, cancellationToken);
    }

    private async Task StoreApiTokenCoreAsync(
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> scopes,
        CachedDownstreamApiTokenEntry tokenEntry,
        CancellationToken cancellationToken)
    {
        var lookupKey = OidcSessionStateApiKey.Create(downstreamApiName, scopes);
        await UpdateStateCoreAsync(
            user,
            state =>
            {
                var next = state.Clone();
                next.ApiTokens[lookupKey] = tokenEntry.Clone();
                return next;
            },
            cancellationToken);
        OidcTokenStoreLog.ApiTokenCacheWrite(logger, downstreamApiName, "success");
    }

    /// <inheritdoc />
    public async Task RemoveAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        await using var localSessionLock = await localSessionCoordinator.AcquireAsync(user, cancellationToken);
        await RemoveCoreAsync(user, cancellationToken);
    }

    /// <inheritdoc />
    public Task RemoveAsync(
        ClaimsPrincipal user,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(localSessionLock);
        return RemoveCoreAsync(user, cancellationToken);
    }

    private async Task RemoveCoreAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        OidcTokenStoreLog.TokenStoreRemoveStarted(logger);
        var state = await GetSessionStateCoreAsync(user, cancellationToken);
        var removedApiTokens = state?.State.ApiTokens.Count ?? 0;
        await DeleteSessionStateCoreAsync(user, cancellationToken);
        OidcTokenStoreLog.TokenStoreRemoveCompleted(logger, removedApiTokens);
    }

    private async Task UpdateStateCoreAsync(
        ClaimsPrincipal user,
        Func<OidcSessionState, OidcSessionState> updater,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var current = await GetSessionStateCoreAsync(user, cancellationToken);
            var nextState = updater(current?.State ?? new OidcSessionState());
            if (await TryCompareAndSwapSessionStateCoreAsync(user, current?.Version, nextState, cancellationToken))
            {
                return;
            }
        }

        throw new InvalidOperationException("The session token state could not be persisted because the stored version changed repeatedly.");
    }

    private async Task<ProtectedSessionStatePayload?> ReadAsync(string cacheKey, CancellationToken cancellationToken)
    {
        var protectedPayload = await distributedCache.GetStringAsync(cacheKey, cancellationToken);
        if (string.IsNullOrWhiteSpace(protectedPayload))
        {
            return default;
        }

        try
        {
            var json = protector.Unprotect(protectedPayload);
            var payload = JsonSerializer.Deserialize<ProtectedSessionStatePayload>(json, SerializerOptions);
            if (!string.Equals(payload?.SchemaVersion, CachePayloadVersion, StringComparison.Ordinal))
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
                nameof(ProtectedSessionStatePayload),
                ex is CryptographicException ? "data-protection" : "json");
            await DeleteCorruptedPayloadAsync(cacheKey, cancellationToken);
            return default;
        }
    }

    private async Task DeleteCorruptedPayloadAsync(string cacheKey, CancellationToken cancellationToken)
    {
        try
        {
            await distributedCache.RemoveAsync(cacheKey, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            OidcTokenStoreLog.TokenStorePayloadCleanupFailed(logger, ex, nameof(ProtectedSessionStatePayload));
        }
    }

    private async Task WriteAsync(
        string cacheKey,
        ProtectedSessionStatePayload payload,
        DateTimeOffset expiresAtUtc,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(payload, SerializerOptions);
        var protectedPayload = protector.Protect(json);
        var utcNow = timeProvider.GetUtcNow();
        var ttl = expiresAtUtc > utcNow
            ? expiresAtUtc - utcNow + TimeSpan.FromHours(12)
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

    private DateTimeOffset ComputeStateExpiration(OidcSessionState state)
    {
        var expirations = state.ApiTokens.Values
            .Select(token => token.ExpiresAtUtc)
            .ToList();
        if (state.SessionTokens is not null)
        {
            expirations.Add(state.SessionTokens.ExpiresAtUtc);
        }

        return expirations.Count == 0
            ? timeProvider.GetUtcNow().AddHours(12)
            : expirations.Max();
    }

    private string BuildSessionCacheKey(ClaimsPrincipal user)
    {
        var context = cacheKeyContextAccessor.GetRequiredContext(user);
        var fingerprint = cacheKeyProtector.CreateSessionFingerprint(context);
        return $"{tokenCacheOptions.Value.CacheKeyPrefix}:session:{fingerprint}";
    }

    private sealed class ProtectedSessionStatePayload
    {
        public string SchemaVersion { get; init; } = string.Empty;

        public string ConcurrencyVersion { get; init; } = string.Empty;

        public OidcSessionState State { get; init; } = new();
    }

}
