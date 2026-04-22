using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class DistributedDownstreamUserTokenStoreTests
{
    [Fact]
    public async Task StoreSessionTokenSetAsync_RoundTripsEntriesBySession()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = CreateStore(distributedCache);

        var user = TestUsers.CreateAuthenticatedUser();
        var tokenSet = new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            IdToken = "id-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        };

        await store.StoreSessionTokenSetAsync(user, tokenSet, CancellationToken.None);
        var entry = await store.GetSessionTokenSetAsync(user, CancellationToken.None);

        Assert.NotNull(entry);
        Assert.Equal("refresh-token", entry!.RefreshToken);
        Assert.Equal("id-token", entry.IdToken);
    }

    [Fact]
    public async Task StoreApiTokenAsync_RoundTripsPerApiEntries()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = CreateStore(distributedCache);
        var user = TestUsers.CreateAuthenticatedUser();
        var tokenEntry = new CachedDownstreamApiTokenEntry
        {
            AccessToken = "api-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        };

        await store.StoreApiTokenAsync(user, "SessionValidationApi", ["openid"], tokenEntry, CancellationToken.None);
        var entry = await store.GetApiTokenAsync(user, "SessionValidationApi", ["openid"], CancellationToken.None);

        Assert.NotNull(entry);
        Assert.Equal("api-token", entry!.AccessToken);
    }

    [Fact]
    public async Task StoreSessionTokenSetAsync_WritesEncryptedPayloadToCache()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = CreateStore(distributedCache);
        var user = TestUsers.CreateAuthenticatedUser();

        await store.StoreSessionTokenSetAsync(user, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            IdToken = "id-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);

        var rawValue = await distributedCache.GetStringAsync("test-cache:session:Duende:https://idp.example.com:user-123:session-123", CancellationToken.None);

        Assert.NotNull(rawValue);
        Assert.DoesNotContain("refresh-token", rawValue, StringComparison.Ordinal);
        Assert.DoesNotContain("id-token", rawValue, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetSessionTokenSetAsync_ReturnsNull_WhenPayloadCannotBeUnprotected()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        await distributedCache.SetStringAsync("test-cache:session:Duende:https://idp.example.com:user-123:session-123", "invalid-payload", CancellationToken.None);
        var store = CreateStore(distributedCache);

        var entry = await store.GetSessionTokenSetAsync(TestUsers.CreateAuthenticatedUser(), CancellationToken.None);

        Assert.Null(entry);
    }

    [Fact]
    public async Task GetSessionTokenSetAsync_LogsWarning_WhenPayloadCannotBeUnprotected()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        await distributedCache.SetStringAsync("test-cache:session:Duende:https://idp.example.com:user-123:session-123", "invalid-payload", CancellationToken.None);
        var logger = new ListLogger<DistributedDownstreamUserTokenStore>();
        var store = CreateStore(distributedCache, logger: logger);

        _ = await store.GetSessionTokenSetAsync(TestUsers.CreateAuthenticatedUser(), CancellationToken.None);

        var warning = Assert.Single(logger.Entries, static entry => entry.Level == LogLevel.Warning);
        Assert.Equal("TokenStorePayloadInvalid", warning.EventId.Name);
        Assert.DoesNotContain("test-cache:session:", warning.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StoreApiTokenAsync_PreservesExpectedTtlPolicy()
    {
        var distributedCache = new RecordingDistributedCache();
        var store = CreateStore(distributedCache);

        await store.StoreApiTokenAsync(
            TestUsers.CreateAuthenticatedUser(),
            "SessionValidationApi",
            ["openid"],
            new CachedDownstreamApiTokenEntry
            {
                AccessToken = "access-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
            },
            CancellationToken.None);

        var apiWrite = Assert.Single(distributedCache.Writes, write => write.Key.Contains(":api:", StringComparison.Ordinal));
        Assert.NotNull(apiWrite.Options);
        Assert.InRange(
            apiWrite.Options.AbsoluteExpirationRelativeToNow!.Value,
            TimeSpan.FromHours(12).Add(TimeSpan.FromMinutes(4)),
            TimeSpan.FromHours(12).Add(TimeSpan.FromMinutes(6)));
    }

    [Fact]
    public async Task StoreApiTokenAsync_UsesProviderIssuerSubjectSessionAndApiInCacheKey()
    {
        var distributedCache = new RecordingDistributedCache();
        var store = CreateStore(distributedCache);

        await store.StoreApiTokenAsync(
            TestUsers.CreateAuthenticatedUser(),
            "SessionValidationApi",
            ["openid"],
            new CachedDownstreamApiTokenEntry
            {
                AccessToken = "access-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
            },
            CancellationToken.None);

        Assert.Contains(
            distributedCache.Writes.Select(write => write.Key),
            key => key.Contains("test-cache:api:Duende:https://idp.example.com:user-123:session-123:SessionValidationApi:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StoreSessionTokenSetAsync_SeparatesEntriesBySession()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = CreateStore(distributedCache);
        var firstUser = TestUsers.CreateAuthenticatedUser(sessionId: "session-a");
        var secondUser = TestUsers.CreateAuthenticatedUser(sessionId: "session-b");

        await store.StoreSessionTokenSetAsync(firstUser, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-a",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);
        await store.StoreSessionTokenSetAsync(secondUser, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-b",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);

        var firstEntry = await store.GetSessionTokenSetAsync(firstUser, CancellationToken.None);
        var secondEntry = await store.GetSessionTokenSetAsync(secondUser, CancellationToken.None);

        Assert.Equal("refresh-a", firstEntry!.RefreshToken);
        Assert.Equal("refresh-b", secondEntry!.RefreshToken);
    }

    [Fact]
    public async Task StoreApiTokenAsync_SeparatesEntriesBySession()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = CreateStore(distributedCache);
        var firstUser = TestUsers.CreateAuthenticatedUser(sessionId: "session-a");
        var secondUser = TestUsers.CreateAuthenticatedUser(sessionId: "session-b");

        await store.StoreApiTokenAsync(firstUser, "SessionValidationApi", ["openid"], new CachedDownstreamApiTokenEntry
        {
            AccessToken = "token-a",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);
        await store.StoreApiTokenAsync(secondUser, "SessionValidationApi", ["openid"], new CachedDownstreamApiTokenEntry
        {
            AccessToken = "token-b",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);

        var firstEntry = await store.GetApiTokenAsync(firstUser, "SessionValidationApi", ["openid"], CancellationToken.None);
        var secondEntry = await store.GetApiTokenAsync(secondUser, "SessionValidationApi", ["openid"], CancellationToken.None);

        Assert.Equal("token-a", firstEntry!.AccessToken);
        Assert.Equal("token-b", secondEntry!.AccessToken);
    }

    [Fact]
    public async Task StoreApiTokenAsync_SeparatesEntriesByIssuer()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = CreateStore(distributedCache);
        var tokenEntry = new CachedDownstreamApiTokenEntry
        {
            AccessToken = "access-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        };

        await store.StoreApiTokenAsync(TestUsers.CreateAuthenticatedUser(subjectId: "user-123", issuer: "https://issuer-a.example.com"), "SessionValidationApi", ["openid"], tokenEntry, CancellationToken.None);
        await store.StoreApiTokenAsync(TestUsers.CreateAuthenticatedUser(subjectId: "user-123", issuer: "https://issuer-b.example.com"), "SessionValidationApi", ["openid"], new CachedDownstreamApiTokenEntry
        {
            AccessToken = "other-token",
            ExpiresAtUtc = tokenEntry.ExpiresAtUtc
        }, CancellationToken.None);

        var firstEntry = await store.GetApiTokenAsync(TestUsers.CreateAuthenticatedUser(subjectId: "user-123", issuer: "https://issuer-a.example.com"), "SessionValidationApi", ["openid"], CancellationToken.None);
        var secondEntry = await store.GetApiTokenAsync(TestUsers.CreateAuthenticatedUser(subjectId: "user-123", issuer: "https://issuer-b.example.com"), "SessionValidationApi", ["openid"], CancellationToken.None);

        Assert.Equal("access-token", firstEntry!.AccessToken);
        Assert.Equal("other-token", secondEntry!.AccessToken);
    }

    [Fact]
    public async Task StoreApiTokenAsync_SeparatesEntriesByProvider()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var firstStore = CreateStore(distributedCache, providerName: "Duende");
        var secondStore = CreateStore(distributedCache, providerName: "AzureADB2C");
        var user = TestUsers.CreateAuthenticatedUser();

        await firstStore.StoreApiTokenAsync(user, "SessionValidationApi", ["openid"], new CachedDownstreamApiTokenEntry
        {
            AccessToken = "first-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);
        await secondStore.StoreApiTokenAsync(user, "SessionValidationApi", ["openid"], new CachedDownstreamApiTokenEntry
        {
            AccessToken = "second-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);

        var firstEntry = await firstStore.GetApiTokenAsync(user, "SessionValidationApi", ["openid"], CancellationToken.None);
        var secondEntry = await secondStore.GetApiTokenAsync(user, "SessionValidationApi", ["openid"], CancellationToken.None);

        Assert.Equal("first-token", firstEntry!.AccessToken);
        Assert.Equal("second-token", secondEntry!.AccessToken);
    }

    [Fact]
    public async Task RemoveAsync_RemovesSessionAndAllApiEntries()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = CreateStore(distributedCache);
        var user = TestUsers.CreateAuthenticatedUser();

        await store.StoreSessionTokenSetAsync(user, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);
        await store.StoreApiTokenAsync(user, "SessionValidationApi", ["openid"], new CachedDownstreamApiTokenEntry
        {
            AccessToken = "access-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);

        await store.RemoveAsync(user, CancellationToken.None);

        Assert.Null(await store.GetSessionTokenSetAsync(user, CancellationToken.None));
        Assert.Null(await store.GetApiTokenAsync(user, "SessionValidationApi", ["openid"], CancellationToken.None));
    }

    [Fact]
    public async Task RemoveAsync_DoesNotRemoveEntriesFromOtherSession()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = CreateStore(distributedCache);
        var firstUser = TestUsers.CreateAuthenticatedUser(sessionId: "session-a");
        var secondUser = TestUsers.CreateAuthenticatedUser(sessionId: "session-b");

        await store.StoreSessionTokenSetAsync(firstUser, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-a",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);
        await store.StoreSessionTokenSetAsync(secondUser, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-b",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);
        await store.StoreApiTokenAsync(firstUser, "SessionValidationApi", ["openid"], new CachedDownstreamApiTokenEntry
        {
            AccessToken = "token-a",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);
        await store.StoreApiTokenAsync(secondUser, "SessionValidationApi", ["openid"], new CachedDownstreamApiTokenEntry
        {
            AccessToken = "token-b",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);

        await store.RemoveAsync(firstUser, CancellationToken.None);

        Assert.Null(await store.GetSessionTokenSetAsync(firstUser, CancellationToken.None));
        Assert.Null(await store.GetApiTokenAsync(firstUser, "SessionValidationApi", ["openid"], CancellationToken.None));
        Assert.Equal("refresh-b", (await store.GetSessionTokenSetAsync(secondUser, CancellationToken.None))!.RefreshToken);
        Assert.Equal("token-b", (await store.GetApiTokenAsync(secondUser, "SessionValidationApi", ["openid"], CancellationToken.None))!.AccessToken);
    }

    [Fact]
    public async Task StoreSessionTokenSetAsync_UsesSubjectClaimIssuer_WhenIssuerClaimIsMissing()
    {
        var distributedCache = new RecordingDistributedCache();
        var store = CreateStore(distributedCache);
        var user = TestUsers.CreateAuthenticatedUser(includeIssuerClaim: false);

        await store.StoreSessionTokenSetAsync(user, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, CancellationToken.None);

        Assert.Contains(
            distributedCache.Writes.Select(write => write.Key),
            key => string.Equals("test-cache:session:Duende:https://idp.example.com:user-123:session-123", key, StringComparison.Ordinal));
    }

    [Fact]
    public async Task StoreSessionTokenSetAsync_Throws_WhenSessionIdCannotBeResolved()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = CreateStore(distributedCache);
        var user = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(
        [
            new System.Security.Claims.Claim("sub", "user-123", System.Security.Claims.ClaimValueTypes.String, "https://idp.example.com"),
            new System.Security.Claims.Claim("iss", "https://idp.example.com")
        ], "test"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => store.StoreSessionTokenSetAsync(
            user,
            new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
            },
            CancellationToken.None));

        Assert.Contains("local session identifier", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StoreSessionTokenSetAsync_Throws_WhenIssuerCannotBeResolved()
    {
        var distributedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = CreateStore(distributedCache);
        var user = TestUsers.CreateAuthenticatedUser(
            [
                new System.Security.Claims.Claim(
                    System.Security.Claims.ClaimTypes.NameIdentifier,
                    "user-123",
                    System.Security.Claims.ClaimValueTypes.String,
                    string.Empty,
                    string.Empty,
                    null)
            ]);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => store.StoreSessionTokenSetAsync(
            user,
            new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
            },
            CancellationToken.None));

        Assert.Contains("issuer identifier", exception.Message, StringComparison.Ordinal);
    }

    private static DistributedDownstreamUserTokenStore CreateStore(
        IDistributedCache distributedCache,
        string providerName = "Duende",
        ILogger<DistributedDownstreamUserTokenStore>? logger = null)
    {
        return new DistributedDownstreamUserTokenStore(
            distributedCache,
            new EphemeralDataProtectionProvider(),
            Options.Create(new TokenCacheOptions
            {
                CacheKeyPrefix = "test-cache"
            }),
            Options.Create(new ActiveOidcProviderOptions
            {
                ProviderName = providerName
            }),
            logger ?? NullLogger<DistributedDownstreamUserTokenStore>.Instance);
    }

    private sealed class RecordingDistributedCache : IDistributedCache
    {
        public List<(string Key, DistributedCacheEntryOptions Options)> Writes { get; } = [];

        public byte[]? Get(string key) => null;

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => Task.FromResult<byte[]?>(null);

        public void Refresh(string key)
        {
        }

        public Task RefreshAsync(string key, CancellationToken token = default) => Task.CompletedTask;

        public void Remove(string key)
        {
        }

        public Task RemoveAsync(string key, CancellationToken token = default) => Task.CompletedTask;

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            Writes.Add((key, options));
        }

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            Writes.Add((key, options));
            return Task.CompletedTask;
        }
    }
}
