using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class OidcDownstreamUserTokenProviderTests
{
    [Fact]
    public async Task GetAccessTokenAsync_RefreshesExpiredTokenForRequestedApi()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var tokenStore = new InMemoryTokenStore(new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        });

        var provider = CreateProvider(
            tokenStore,
            new StubHttpClientFactory(CreateTokenResponse(
                accessToken: "fresh-token",
                refreshToken: "fresh-refresh")));

        var token = await provider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);

        Assert.Equal("fresh-token", token);
        Assert.NotNull(tokenStore.StoredSessionTokenSet);
        Assert.Equal("fresh-refresh", tokenStore.StoredSessionTokenSet!.RefreshToken);
        var cachedEntry = await tokenStore.GetApiTokenAsync(user, "SessionValidationApi", ["openid"], CancellationToken.None);
        Assert.NotNull(cachedEntry);
        Assert.Equal("fresh-token", cachedEntry!.AccessToken);
    }

    [Fact]
    public async Task GetAccessTokenAsync_UsesDedicatedNamedHttpClientForRefresh()
    {
        var factory = new RecordingHttpClientFactory(_ => new HttpClient(new CaptureRequestHandler())
        {
            BaseAddress = new Uri("https://idp.example.com")
        });
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            factory);

        var token = await provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None);

        Assert.Equal("captured-token", token);
        Assert.Equal(1, factory.CreateClientCount);
        Assert.Equal("Recrovit.OpenIdConnect.TokenEndpoint", factory.LastClientName);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ReusesCachedTokenForSameApi()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var existingEntry = new CachedDownstreamApiTokenEntry
        {
            AccessToken = "cached-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        };
        var tokenStore = new InMemoryTokenStore(
            new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            },
            new Dictionary<string, CachedDownstreamApiTokenEntry>
            {
                ["SessionValidationApi:openid"] = existingEntry
            });

        var token = await CreateProvider(tokenStore, new StubHttpClientFactory("{}"))
            .GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);

        Assert.Equal("cached-token", token);
        Assert.Single(tokenStore.ApiTokens);
    }

    [Fact]
    public async Task GetAccessTokenAsync_UsesSeparateRefreshRequestsForDifferentApis()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var handler = new CaptureRequestHandler();
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new DelegatingHttpClientFactory(handler));

        _ = await provider.GetAccessTokenAsync(user, "GraphApi", CancellationToken.None);

        Assert.Contains("scope=graph.read", handler.LastRequestContent, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetAccessTokenAsync_PublicConstructorWithoutAssertionService_RefreshesForClientSecretPost()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var tokenStore = new InMemoryTokenStore(new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        });
        var handler = new CaptureRequestHandler();
        var provider = CreateDirectProvider(tokenStore, new DelegatingHttpClientFactory(handler));

        var token = await provider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);

        Assert.Equal("captured-token", token);
        Assert.NotNull(handler.LastRequestContent);
        Assert.Contains("client_secret=client-secret", handler.LastRequestContent, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetAccessTokenAsync_PublicConstructorWithAssertionService_UsesClientAssertion_WhenConfiguredForPrivateKeyJwt()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var tokenStore = new InMemoryTokenStore(new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        });
        var handler = new CaptureRequestHandler();
        var provider = CreateDirectProvider(
            tokenStore,
            new DelegatingHttpClientFactory(handler),
            oidcOptions: CreateProviderOptions(OidcClientAuthenticationMethod.PrivateKeyJwt),
            clientAssertionService: new FixedClientAssertionService("direct-client-assertion"));

        var token = await provider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);

        Assert.Equal("captured-token", token);
        Assert.NotNull(handler.LastRequestContent);
        Assert.Contains("client_assertion=direct-client-assertion", handler.LastRequestContent, StringComparison.Ordinal);
        Assert.Contains("client_assertion_type=", handler.LastRequestContent, StringComparison.Ordinal);
        Assert.DoesNotContain("client_secret=", handler.LastRequestContent, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetAccessTokenAsync_PublicConstructorWithoutAssertionService_ThrowsClearError_WhenConfiguredForPrivateKeyJwt()
    {
        var provider = CreateDirectProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory("{}"),
            oidcOptions: CreateProviderOptions(OidcClientAuthenticationMethod.PrivateKeyJwt));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));

        Assert.Equal("PrivateKeyJwt authentication requires the OIDC client assertion service.", ex.Message);
    }

    [Fact]
    public async Task GetAccessTokenAsync_UsesClientAssertion_WhenConfiguredForPrivateKeyJwt()
    {
        using var certificate = TestCertificates.CreateTemporaryPfx();
        var handler = new CaptureRequestHandler();
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new DelegatingHttpClientFactory(handler),
            configurationOverrides: CreatePrivateKeyJwtOverrides(certificate));

        _ = await provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None);

        Assert.NotNull(handler.LastRequestContent);
        Assert.Contains("client_assertion_type=", handler.LastRequestContent, StringComparison.Ordinal);
        Assert.Contains("client_assertion=", handler.LastRequestContent, StringComparison.Ordinal);
        Assert.DoesNotContain("client_secret=", handler.LastRequestContent, StringComparison.Ordinal);

        var formValues = ParseFormBody(handler.LastRequestContent);
        var token = new JsonWebToken(formValues[OpenIdConnectParameterNames.ClientAssertion]);
        Assert.Equal("client-id", token.Issuer);
        Assert.Equal("client-id", token.Subject);
        Assert.Contains("https://idp.example.com/connect/token", token.Audiences);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ReusesCachedCertificate_ForPrivateKeyJwtAfterCertificateFileIsDeleted()
    {
        using var certificate = TestCertificates.CreateTemporaryPfx();
        var handler = new CaptureRequestHandler("""{"access_token":"captured-token","expires_in":0}""");
        var user = TestUsers.CreateAuthenticatedUser(sessionId: "session-a");
        var provider = CreateProvider(
            new InMemoryTokenStore(user, new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new DelegatingHttpClientFactory(handler),
            configurationOverrides: CreatePrivateKeyJwtOverrides(certificate));

        _ = await provider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);

        File.Delete(certificate.Path);

        var token = await provider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);

        Assert.Equal("captured-token", token);
        Assert.NotNull(handler.LastRequestContent);
        Assert.Contains("client_assertion=", handler.LastRequestContent, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetAccessTokenAsync_DoesNotLogWarning_WhenJwtScopeClaimContainsRequestedScopes()
    {
        var loggerFactory = new ListLoggerFactory();
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory($$"""
            {
              "{{OpenIdConnectParameterNames.AccessToken}}": "{{CreateJwtAccessToken((OidcAuthenticationConstants.TokenNames.Scope, "openid profile"))}}",
              "{{OidcAuthenticationConstants.TokenNames.ExpiresIn}}": 120
            }
            """),
            loggerFactory: loggerFactory);

        _ = await provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None);

        Assert.DoesNotContain(loggerFactory.Entries, entry => entry.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task GetAccessTokenAsync_DoesNotLogWarning_WhenJwtScpClaimContainsRequestedScopes()
    {
        var loggerFactory = new ListLoggerFactory();
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory($$"""
            {
              "{{OpenIdConnectParameterNames.AccessToken}}": "{{CreateJwtAccessToken((OidcAuthenticationConstants.TokenNames.Scp, "openid"))}}",
              "{{OidcAuthenticationConstants.TokenNames.ExpiresIn}}": 120
            }
            """),
            loggerFactory: loggerFactory);

        _ = await provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None);

        Assert.DoesNotContain(loggerFactory.Entries, entry => entry.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task GetAccessTokenAsync_LogsWarning_WhenJwtScopeClaimMissesRequestedScopes_ButStillCachesToken()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var loggerFactory = new ListLoggerFactory();
        var tokenStore = new InMemoryTokenStore(new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        });
        var accessToken = CreateJwtAccessToken((OidcAuthenticationConstants.TokenNames.Scope, "profile"));
        var provider = CreateProvider(
            tokenStore,
            new StubHttpClientFactory($$"""
            {
              "{{OpenIdConnectParameterNames.AccessToken}}": "{{accessToken}}",
              "{{OidcAuthenticationConstants.TokenNames.ExpiresIn}}": 120
            }
            """),
            loggerFactory: loggerFactory);

        var token = await provider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);

        Assert.Equal(accessToken, token);
        var warning = Assert.Single(loggerFactory.Entries, entry => entry.Level == LogLevel.Warning);
        Assert.Equal("ScopeValidationMismatch", warning.EventId.Name);
        Assert.DoesNotContain(accessToken, warning.Message, StringComparison.Ordinal);
        Assert.NotNull(await tokenStore.GetApiTokenAsync(user, "SessionValidationApi", ["openid"], CancellationToken.None));
    }

    [Fact]
    public async Task GetAccessTokenAsync_LogsWarning_WhenJwtHasNoScopeOrScpClaim()
    {
        var loggerFactory = new ListLoggerFactory();
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory($$"""
            {
              "{{OpenIdConnectParameterNames.AccessToken}}": "{{CreateJwtAccessToken(("aud", "api"))}}",
              "{{OidcAuthenticationConstants.TokenNames.ExpiresIn}}": 120
            }
            """),
            loggerFactory: loggerFactory);

        _ = await provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None);

        var warning = Assert.Single(loggerFactory.Entries, entry => entry.Level == LogLevel.Warning);
        Assert.Equal("ScopeValidationIncomplete", warning.EventId.Name);
    }

    [Fact]
    public async Task GetAccessTokenAsync_DoesNotLogWarning_WhenTokenIsOpaque()
    {
        var loggerFactory = new ListLoggerFactory();
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory(CreateTokenResponse(accessToken: "opaque-token")),
            loggerFactory: loggerFactory);

        _ = await provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None);

        Assert.DoesNotContain(loggerFactory.Entries, entry => entry.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ReusesSingleRefreshAcrossConcurrentRequestsForSameApi()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var tokenStore = new InMemoryTokenStore(new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        });
        var refreshHandler = new CoordinatedRefreshHandler(CreateTokenResponse(
            accessToken: "fresh-token",
            refreshToken: "fresh-refresh"));

        var provider = CreateProvider(tokenStore, new DelegatingHttpClientFactory(refreshHandler));

        var firstCall = provider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);
        await refreshHandler.FirstRequestStarted;

        var secondCall = provider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);
        await Task.Delay(50, TestContext.Current.CancellationToken);

        Assert.False(secondCall.IsCompleted);
        Assert.Equal(1, refreshHandler.RequestCount);

        refreshHandler.ReleaseFirstResponse();

        var tokens = await Task.WhenAll(firstCall, secondCall);

        Assert.Equal(["fresh-token", "fresh-token"], tokens);
        Assert.Equal(1, refreshHandler.RequestCount);
    }

    [Fact]
    public async Task GetAccessTokenAsync_LogoutWaitsForRefreshAndRemovesRefreshedStateLast()
    {
        using var coordinatorServices = CreateCoordinatorServiceProvider();
        var coordinator = coordinatorServices.GetRequiredService<ILocalOidcSessionCoordinator>();
        var user = TestUsers.CreateAuthenticatedUser();
        var tokenStore = new InMemoryTokenStore(user, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        });
        var refreshHandler = new CoordinatedRefreshHandler(CreateTokenResponse(
            accessToken: "fresh-token",
            refreshToken: "fresh-refresh"));
        var provider = CreateProvider(
            tokenStore,
            new DelegatingHttpClientFactory(refreshHandler),
            localSessionCoordinator: coordinator);

        var refresh = provider.GetAccessTokenAsync(user, "SessionValidationApi", TestContext.Current.CancellationToken);
        await refreshHandler.FirstRequestStarted;

        var logout = Task.Run(async () =>
        {
            await using var localSessionLock = await coordinator.AcquireAsync(user, TestContext.Current.CancellationToken);
            await ((IDownstreamUserTokenStore)tokenStore).RemoveAsync(
                user,
                localSessionLock,
                TestContext.Current.CancellationToken);
        }, TestContext.Current.CancellationToken);

        await Task.Delay(50, TestContext.Current.CancellationToken);
        Assert.False(logout.IsCompleted);

        refreshHandler.ReleaseFirstResponse();

        Assert.Equal("fresh-token", await refresh);
        await logout;
        Assert.Null(await tokenStore.GetSessionStateAsync(user, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetAccessTokenAsync_DoesNotRefreshOrRestoreStateAfterLogoutOwnsSessionLock()
    {
        using var coordinatorServices = CreateCoordinatorServiceProvider();
        var coordinator = coordinatorServices.GetRequiredService<ILocalOidcSessionCoordinator>();
        var user = TestUsers.CreateAuthenticatedUser();
        var tokenStore = new InMemoryTokenStore(user, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        });
        var handler = new CaptureRequestHandler(CreateTokenResponse(
            accessToken: "fresh-token",
            refreshToken: "fresh-refresh"));
        var provider = CreateProvider(
            tokenStore,
            new DelegatingHttpClientFactory(handler),
            localSessionCoordinator: coordinator);
        var logoutLock = await coordinator.AcquireAsync(user, TestContext.Current.CancellationToken);
        await ((IDownstreamUserTokenStore)tokenStore).RemoveAsync(
            user,
            logoutLock,
            TestContext.Current.CancellationToken);

        var refresh = provider.GetAccessTokenAsync(user, "SessionValidationApi", TestContext.Current.CancellationToken);
        await Task.Delay(50, TestContext.Current.CancellationToken);

        Assert.False(refresh.IsCompleted);
        Assert.Equal(0, handler.RequestCount);

        await logoutLock.DisposeAsync();

        await Assert.ThrowsAsync<OidcReauthenticationRequiredException>(() => refresh);
        Assert.Equal(0, handler.RequestCount);
        Assert.Null(await tokenStore.GetSessionStateAsync(user, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetAccessTokenAsync_UsesSeparateRefreshLocksForDifferentSessions()
    {
        var firstUser = TestUsers.CreateAuthenticatedUser(sessionId: "session-a");
        var secondUser = TestUsers.CreateAuthenticatedUser(sessionId: "session-b");
        var tokenStore = new InMemoryTokenStore();
        await tokenStore.StoreSessionTokenSetAsync(firstUser, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-a",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        }, CancellationToken.None);
        await tokenStore.StoreSessionTokenSetAsync(secondUser, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-b",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        }, CancellationToken.None);

        var handler = new CoordinatedRefreshHandler(CreateTokenResponse(
            accessToken: "fresh-token",
            refreshToken: "fresh-refresh"));
        var provider = CreateProvider(tokenStore, new DelegatingHttpClientFactory(handler));

        var firstCall = provider.GetAccessTokenAsync(firstUser, "SessionValidationApi", CancellationToken.None);
        await handler.FirstRequestStarted;

        var secondCall = provider.GetAccessTokenAsync(secondUser, "SessionValidationApi", CancellationToken.None);
        await Task.Delay(50, TestContext.Current.CancellationToken);

        Assert.True(secondCall.IsCompleted);
        Assert.Equal(2, handler.RequestCount);

        handler.ReleaseFirstResponse();

        var tokens = await Task.WhenAll(firstCall, secondCall);

        Assert.Equal(["fresh-token", "fresh-token"], tokens);
    }

    [Fact]
    public async Task GetAccessTokenAsync_MergesLatestStoredState_WhenCompareAndSwapLosesConcurrentUpdates()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var timeProvider = new FixedTimeProvider(DateTimeOffset.Parse("2026-07-31T10:00:00Z"));
        var tokenStore = new CompareAndSwapConflictSessionStateStore(
            new OidcSessionState
            {
                SessionTokens = new StoredOidcSessionTokenSet
                {
                    RefreshToken = "refresh-token",
                    ExpiresAtUtc = timeProvider.GetUtcNow().AddHours(1)
                },
                ApiTokens = new Dictionary<string, CachedDownstreamApiTokenEntry>(StringComparer.Ordinal)
                {
                    [CreateApiKey("GraphApi", ["graph.read"])] = new CachedDownstreamApiTokenEntry
                    {
                        AccessToken = "graph-token-0",
                        ExpiresAtUtc = timeProvider.GetUtcNow().AddMinutes(2)
                    }
                },
                LastRefreshUtc = timeProvider.GetUtcNow().AddMinutes(-2)
            },
            [
                new OidcSessionState
                {
                    SessionTokens = new StoredOidcSessionTokenSet
                    {
                        RefreshToken = "refresh-token",
                        ExpiresAtUtc = timeProvider.GetUtcNow().AddHours(1)
                    },
                    ApiTokens = new Dictionary<string, CachedDownstreamApiTokenEntry>(StringComparer.Ordinal)
                    {
                        [CreateApiKey("GraphApi", ["graph.read"])] = new CachedDownstreamApiTokenEntry
                        {
                            AccessToken = "graph-token-1",
                            ExpiresAtUtc = timeProvider.GetUtcNow().AddMinutes(3)
                        }
                    },
                    LastRefreshUtc = timeProvider.GetUtcNow().AddMinutes(-1)
                },
                new OidcSessionState
                {
                    SessionTokens = new StoredOidcSessionTokenSet
                    {
                        RefreshToken = "refresh-token",
                        ExpiresAtUtc = timeProvider.GetUtcNow().AddHours(1)
                    },
                    ApiTokens = new Dictionary<string, CachedDownstreamApiTokenEntry>(StringComparer.Ordinal)
                    {
                        [CreateApiKey("GraphApi", ["graph.read"])] = new CachedDownstreamApiTokenEntry
                        {
                            AccessToken = "graph-token-2",
                            ExpiresAtUtc = timeProvider.GetUtcNow().AddMinutes(4)
                        }
                    },
                    LastRefreshUtc = timeProvider.GetUtcNow().AddSeconds(-30)
                }
            ]);
        var handler = new CaptureRequestHandler(CreateTokenResponse(
            accessToken: "fresh-token",
            refreshToken: "fresh-refresh"));
        var provider = CreateProvider(
            tokenStore,
            new DelegatingHttpClientFactory(handler),
            timeProvider: timeProvider);

        var token = await provider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);

        Assert.Equal("fresh-token", token);
        Assert.Equal(1, handler.RequestCount);
        Assert.Equal(3, tokenStore.CompareAndSwapAttempts);
        Assert.Equal("fresh-token", tokenStore.CurrentState.State.ApiTokens[CreateApiKey("SessionValidationApi", ["openid"])].AccessToken);
        Assert.Equal("graph-token-2", tokenStore.CurrentState.State.ApiTokens[CreateApiKey("GraphApi", ["graph.read"])].AccessToken);
        Assert.Equal("fresh-refresh", tokenStore.CurrentState.State.SessionTokens!.RefreshToken);
        Assert.Equal(timeProvider.GetUtcNow(), tokenStore.CurrentState.State.LastRefreshUtc);
    }

    [Fact]
    public async Task GetAccessTokenAsync_DoesNotPersistRefreshResult_WhenSessionWasRemovedAfterCompareAndSwapConflict()
    {
        var timeProvider = new FixedTimeProvider(DateTimeOffset.Parse("2026-07-31T10:00:00Z"));
        var tokenStore = new CompareAndSwapConflictSessionStateStore(
            new OidcSessionState
            {
                SessionTokens = new StoredOidcSessionTokenSet
                {
                    RefreshToken = "refresh-token",
                    ExpiresAtUtc = timeProvider.GetUtcNow().AddHours(1)
                }
            },
            [new OidcSessionState()]);
        var provider = CreateProvider(
            tokenStore,
            new StubHttpClientFactory(CreateTokenResponse("fresh-token", "fresh-refresh")),
            timeProvider: timeProvider);

        await Assert.ThrowsAsync<OidcReauthenticationRequiredException>(() => provider.GetAccessTokenAsync(
            TestUsers.CreateAuthenticatedUser(),
            "SessionValidationApi",
            TestContext.Current.CancellationToken));

        Assert.Equal(1, tokenStore.CompareAndSwapAttempts);
        Assert.Null(tokenStore.CurrentState.State.SessionTokens);
        Assert.Empty(tokenStore.CurrentState.State.ApiTokens);
    }

    [Fact]
    public async Task GetAccessTokenAsync_PersistsRefreshResult_WhenLocalLockDoesNotExpireByTime()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var tokenStore = new InMemoryTokenStore(user, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        });
        var timeProvider = new MutableTimeProvider(DateTimeOffset.UtcNow);
        var loggerFactory = new ListLoggerFactory();
        var handler = new AdvanceTimeHandler(
            CreateTokenResponse(accessToken: "fresh-token", refreshToken: "fresh-refresh"),
            timeProvider,
            TimeSpan.FromSeconds(5));
        var provider = CreateProvider(
            tokenStore,
            new DelegatingHttpClientFactory(handler),
            loggerFactory: loggerFactory,
            timeProvider: timeProvider);

        var token = await provider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);

        Assert.Equal("fresh-token", token);
        Assert.Equal(1, handler.RequestCount);
        Assert.Equal("fresh-refresh", tokenStore.StoredSessionTokenSet!.RefreshToken);
        Assert.Equal("fresh-token", (await tokenStore.GetApiTokenAsync(user, "SessionValidationApi", ["openid"], CancellationToken.None))!.AccessToken);
        Assert.DoesNotContain(loggerFactory.Entries, entry => entry.EventId.Name == "RefreshLockLeaseExpired");
    }

    [Fact]
    public async Task GetAccessTokenAsync_ThrowsAndDoesNotPersist_WhenRefreshLeaseExpiresBeforeResponseReturns()
    {
        var now = DateTimeOffset.Parse("2026-07-31T10:00:00Z");
        var user = TestUsers.CreateAuthenticatedUser();
        var timeProvider = new MutableTimeProvider(now);
        var tokenStore = new InMemoryTokenStore(user, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = now.AddHours(1)
        });
        var provider = CreateProvider(
            tokenStore,
            new DelegatingHttpClientFactory(new AdvanceTimeHandler(
                CreateTokenResponse(accessToken: "fresh-token", refreshToken: "fresh-refresh"),
                timeProvider,
                TimeSpan.FromSeconds(5))),
            refreshLockProvider: new FixedLeaseRefreshLockProvider("lease-owner", now.AddSeconds(1)),
            timeProvider: timeProvider);

        var ex = await Assert.ThrowsAsync<OidcTokenRefreshFailedException>(() =>
            provider.GetAccessTokenAsync(user, "SessionValidationApi", TestContext.Current.CancellationToken));

        Assert.Contains("lease expired", ex.Message, StringComparison.OrdinalIgnoreCase);

        var latestState = await tokenStore.GetSessionStateAsync(user, TestContext.Current.CancellationToken);
        Assert.NotNull(latestState);
        Assert.Equal("refresh-token", latestState!.State.SessionTokens!.RefreshToken);
        Assert.Empty(latestState.State.ApiTokens);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ThrowsTokenRefreshFailed_WhenTokenEndpointRequestTimesOut()
    {
        var tokenEndpoint = new Uri("http://127.0.0.1/connect/token", UriKind.Absolute);
        var oidcOptions = CreateProviderOptions(tokenEndpointTimeout: TimeSpan.FromMilliseconds(50));
        var provider = CreateDirectProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new RecordingHttpClientFactory(_ => new HttpClient(new DelayedResponseHandler(TimeSpan.FromSeconds(1)))
            {
                Timeout = TimeSpan.FromMilliseconds(50)
            }),
            oidcOptions: oidcOptions,
            openIdOptionsMonitor: new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
            {
                Configuration = new OpenIdConnectConfiguration
                {
                    TokenEndpoint = tokenEndpoint.AbsoluteUri
                },
                ConfigurationManager = null
            }));

        var ex = await Assert.ThrowsAsync<OidcTokenRefreshFailedException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));

        Assert.Contains("timed out", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ReusesConcurrentTokenOrReauthenticates_WhenRefreshFailsWithInvalidGrant()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var concurrentStore = new InMemoryTokenStore(user, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
        });
        var concurrentHandler = new CallbackHttpMessageHandler(() =>
        {
            concurrentStore.StoreSessionTokenSetAsync(
                user,
                new StoredOidcSessionTokenSet
                {
                    RefreshToken = "rotated-refresh-token",
                    ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
                },
                CancellationToken.None).GetAwaiter().GetResult();
            concurrentStore.StoreApiTokenAsync(
                user,
                "SessionValidationApi",
                ["openid"],
                new CachedDownstreamApiTokenEntry
                {
                    AccessToken = "concurrent-token",
                    ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
                },
                CancellationToken.None).GetAwaiter().GetResult();
            return new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent(CreateErrorResponse(OidcAuthenticationConstants.OAuthErrors.InvalidGrant))
            };
        });
        var concurrentProvider = CreateProvider(
            concurrentStore,
            new DelegatingHttpClientFactory(concurrentHandler));

        var reusedToken = await concurrentProvider.GetAccessTokenAsync(user, "SessionValidationApi", CancellationToken.None);

        Assert.Equal("concurrent-token", reusedToken);

        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory(
                CreateErrorResponse(OidcAuthenticationConstants.OAuthErrors.InvalidGrant),
                HttpStatusCode.BadRequest));

        var ex = await Assert.ThrowsAsync<OidcReauthenticationRequiredException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));

        Assert.Contains("Refresh token exchange failed", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetAccessTokenAsync_LogsRefreshFlowEventsWithoutSensitiveValues()
    {
        var loggerFactory = new ListLoggerFactory();
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token-secret",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory(CreateTokenResponse(
                accessToken: "fresh-token",
                refreshToken: "fresh-refresh")),
            loggerFactory: loggerFactory);

        _ = await provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None);

        var eventNames = loggerFactory.Entries.Select(static entry => entry.EventId.Name).ToArray();
        Assert.Equal("AccessTokenRequested", eventNames[0]);
        Assert.Contains(eventNames, static name => name == "RefreshLockAcquired");
        Assert.Contains(eventNames, static name => name == "OidcMetadataRequested");
        Assert.Contains(eventNames, static name => name == "RefreshRequestStarted");
        Assert.Contains(eventNames, static name => name == "RefreshResponseReceived");
        Assert.Contains(eventNames, static name => name == "RefreshResponseParsed");
        Assert.Contains(eventNames, static name => name == "RefreshedTokensStored");
        Assert.DoesNotContain(loggerFactory.Entries, entry => entry.Message.Contains("refresh-token-secret", StringComparison.Ordinal));
        Assert.DoesNotContain(loggerFactory.Entries, entry => entry.Message.Contains("fresh-token", StringComparison.Ordinal));
        Assert.DoesNotContain(loggerFactory.Entries, entry => entry.Message.Contains("fresh-refresh", StringComparison.Ordinal));
    }

    [Fact]
    public async Task GetAccessTokenAsync_ThrowsReauthenticationRequired_WhenSessionTokenMissing()
    {
        var provider = CreateProvider(new InMemoryTokenStore(), new StubHttpClientFactory("{}"));

        var ex = await Assert.ThrowsAsync<OidcReauthenticationRequiredException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));

        Assert.Contains("No stored token set", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ThrowsTokenRefreshFailed_WhenRefreshReturnsServerError()
    {
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory(
                CreateErrorResponse("temporarily_unavailable"),
                HttpStatusCode.ServiceUnavailable));

        await Assert.ThrowsAsync<OidcTokenRefreshFailedException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));
    }

    [Fact]
    public async Task GetAccessTokenAsync_ThrowsTokenRefreshFailed_WhenRefreshReturnsNonReauthenticationClientError()
    {
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory(
                CreateErrorResponse("invalid_client"),
                HttpStatusCode.BadRequest));

        await Assert.ThrowsAsync<OidcTokenRefreshFailedException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));
    }

    [Fact]
    public async Task GetAccessTokenAsync_ThrowsTokenRefreshFailed_WhenMetadataLoadFails()
    {
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory("{}"),
            openIdOptionsMonitor: new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
            {
                ConfigurationManager = new ThrowingConfigurationManager()
            }));

        await Assert.ThrowsAsync<OidcTokenRefreshFailedException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));
    }

    [Fact]
    public async Task GetAccessTokenAsync_RefreshesExpiredToken_WhenStaticConfigurationProvidesTokenEndpoint()
    {
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory(CreateTokenResponse(
                accessToken: "fresh-token",
                refreshToken: "fresh-refresh")),
            openIdOptionsMonitor: new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
            {
                Configuration = new OpenIdConnectConfiguration
                {
                    TokenEndpoint = "https://idp.example.com/connect/token"
                },
                ConfigurationManager = null
            }));

        var token = await provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None);

        Assert.Equal("fresh-token", token);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ThrowsTokenRefreshFailed_WhenNoTokenEndpointCanBeResolved()
    {
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory("{}"),
            openIdOptionsMonitor: new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
            {
                Configuration = new OpenIdConnectConfiguration(),
                ConfigurationManager = null
            }));

        var ex = await Assert.ThrowsAsync<OidcTokenRefreshFailedException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));

        Assert.Equal(
            "The OIDC token endpoint is not available from the static configuration or the OIDC metadata.",
            ex.Message);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ThrowsTokenRefreshFailed_WhenProductionTokenEndpointIsNotHttps()
    {
        var handler = new CaptureRequestHandler();
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new DelegatingHttpClientFactory(handler),
            environment: new FakeWebHostEnvironment { EnvironmentName = Environments.Production },
            openIdOptionsMonitor: new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
            {
                ConfigurationManager = new StaticConfigurationManager("http://idp.example.com/connect/token")
            }));

        var ex = await Assert.ThrowsAsync<OidcTokenRefreshFailedException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));

        Assert.Contains("absolute HTTPS URI", ex.Message, StringComparison.Ordinal);
        Assert.Null(handler.LastRequest);
    }

    [Fact]
    public async Task GetAccessTokenAsync_AllowsNonHttpsTokenEndpointOutsideProduction()
    {
        var provider = CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1)
            }),
            new StubHttpClientFactory(CreateTokenResponse(
                accessToken: "fresh-token",
                refreshToken: "fresh-refresh")),
            openIdOptionsMonitor: new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
            {
                ConfigurationManager = new StaticConfigurationManager("http://idp.example.com/connect/token")
            }));

        var token = await provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None);

        Assert.Equal("fresh-token", token);
    }

    private static IDownstreamUserTokenProvider CreateProvider(
        IDownstreamUserTokenStore tokenStore,
        IHttpClientFactory httpClientFactory,
        FakeWebHostEnvironment? environment = null,
        ListLoggerFactory? loggerFactory = null,
        IOptionsMonitor<OpenIdConnectOptions>? openIdOptionsMonitor = null,
        Dictionary<string, string?>? configurationOverrides = null,
        IOidcSessionStateStore? sessionStateStore = null,
        IOidcSessionRefreshLockProvider? refreshLockProvider = null,
        ILocalOidcSessionCoordinator? localSessionCoordinator = null,
        TimeProvider? timeProvider = null)
    {
        var services = new ServiceCollection();
        environment ??= new FakeWebHostEnvironment { EnvironmentName = Environments.Development };
        services.AddLogging();
        var overrides = new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:BaseUrl"] = "https://api.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:Scopes:0"] = "openid",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:GraphApi:BaseUrl"] = "https://graph.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:GraphApi:Scopes:0"] = "graph.read"
        };
        if (configurationOverrides is not null)
        {
            foreach (var (key, value) in configurationOverrides)
            {
                overrides[key] = value;
            }
        }

        services.AddOidcAuthenticationInfrastructure(TestConfiguration.Build(overrides), environment);
        services.Replace(ServiceDescriptor.Scoped<IDownstreamUserTokenStore>(_ => tokenStore));
        services.Replace(ServiceDescriptor.Scoped<IOidcSessionStateStore>(_ =>
            sessionStateStore ?? (tokenStore as IOidcSessionStateStore ?? throw new InvalidOperationException("Token store must implement IOidcSessionStateStore."))));
        services.Replace(ServiceDescriptor.Singleton(httpClientFactory));
        services.Replace(ServiceDescriptor.Singleton<IOptionsMonitor<OpenIdConnectOptions>>(openIdOptionsMonitor ?? new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
        {
            ConfigurationManager = new StaticConfigurationManager("https://idp.example.com/connect/token")
        })));

        if (refreshLockProvider is not null)
        {
            services.Replace(ServiceDescriptor.Singleton(refreshLockProvider));
        }

        if (localSessionCoordinator is not null)
        {
            services.Replace(ServiceDescriptor.Singleton(localSessionCoordinator));
        }

        if (timeProvider is not null)
        {
            services.Replace(ServiceDescriptor.Singleton(timeProvider));
        }

        if (loggerFactory is not null)
        {
            services.Replace(ServiceDescriptor.Singleton<ILoggerFactory>(loggerFactory));
        }

        var serviceProvider = services.BuildServiceProvider();
        return serviceProvider.GetRequiredService<IDownstreamUserTokenProvider>();
    }

    private static ServiceProvider CreateCoordinatorServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOidcAuthenticationInfrastructure(TestConfiguration.Build(), new FakeWebHostEnvironment());
        return services.BuildServiceProvider();
    }

    private static OidcDownstreamUserTokenProvider CreateDirectProvider(
        InMemoryTokenStore tokenStore,
        IHttpClientFactory httpClientFactory,
        OidcProviderOptions? oidcOptions = null,
        IOidcClientAssertionService? clientAssertionService = null,
        IOptionsMonitor<OpenIdConnectOptions>? openIdOptionsMonitor = null)
    {
        oidcOptions ??= CreateProviderOptions();

        return new OidcDownstreamUserTokenProvider(
            tokenStore,
            TestFactories.CreateDownstreamApiCatalog(),
            Options.Create(oidcOptions),
            Options.Create(new ActiveOidcProviderOptions { ProviderName = "Duende" }),
            Options.Create(TestFactories.CreateTokenCacheOptions()),
            new LoggerFactory().CreateLogger<OidcDownstreamUserTokenProvider>(),
            httpClientFactory,
            new FakeHostEnvironment { EnvironmentName = Environments.Development },
            openIdOptionsMonitor ?? new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
            {
                ConfigurationManager = new StaticConfigurationManager("https://idp.example.com/connect/token")
            }),
            clientAssertionService);
    }

    private static OidcProviderOptions CreateProviderOptions(
        OidcClientAuthenticationMethod clientAuthenticationMethod = OidcClientAuthenticationMethod.ClientSecretPost,
        TimeSpan? tokenEndpointTimeout = null)
    {
        return new OidcProviderOptions
        {
            Authority = "https://idp.example.com",
            ClientId = "client-id",
            ClientSecret = clientAuthenticationMethod == OidcClientAuthenticationMethod.ClientSecretPost
                ? "client-secret"
                : null,
            ClientAuthenticationMethod = clientAuthenticationMethod,
            Scopes = ["openid", "profile"],
            TokenEndpointTimeout = tokenEndpointTimeout ?? TimeSpan.FromSeconds(30)
        };
    }

    private static string CreateJwtAccessToken((string Name, string Value) claim)
        => CreateJwtAccessToken([claim]);

    private static string CreateApiKey(string downstreamApiName, IReadOnlyCollection<string> scopes)
    {
        var normalizedScopes = scopes
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .Select(scope => scope.Trim())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(scope => scope, StringComparer.Ordinal);
        var serializedScopes = string.Join(" ", normalizedScopes);
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(serializedScopes));
        return $"{downstreamApiName}:{Convert.ToHexString(hash)}";
    }

    private static string CreateTokenResponse(string accessToken, string? refreshToken = null)
    {
        var response = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            [OpenIdConnectParameterNames.AccessToken] = accessToken,
            [OidcAuthenticationConstants.TokenNames.ExpiresIn] = 120
        };

        if (refreshToken is not null)
        {
            response[OpenIdConnectParameterNames.RefreshToken] = refreshToken;
        }

        return JsonSerializer.Serialize(response);
    }

    private static string CreateErrorResponse(string errorCode)
        => $$"""{"{{OidcAuthenticationConstants.TokenNames.Error}}":"{{errorCode}}"}""";

    private static string CreateJwtAccessToken(params (string Name, string Value)[] claims)
    {
        var payload = string.Join(",", claims.Select(claim => $"\"{claim.Name}\":\"{claim.Value}\""));
        return $"{Base64UrlEncode("""{"alg":"none"}""")}.{Base64UrlEncode($"{{{payload}}}")}.";
    }

    private static string Base64UrlEncode(string value)
    {
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static Dictionary<string, string?> CreatePrivateKeyJwtOverrides(TemporaryPfxCertificate certificate)
    {
        return new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:ClientAuthenticationMethod"] = "PrivateKeyJwt",
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:ClientSecret"] = null,
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:ClientCertificate:Source"] = "File",
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:ClientCertificate:File:Path"] = certificate.Path,
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:ClientCertificate:File:Password"] = certificate.Password
        };
    }

    private static Dictionary<string, string> ParseFormBody(string? body)
    {
        Assert.False(string.IsNullOrWhiteSpace(body));

        return body!
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .ToDictionary(
                parts => Uri.UnescapeDataString(parts[0].Replace("+", "%20", StringComparison.Ordinal)),
                parts => parts.Length > 1
                    ? Uri.UnescapeDataString(parts[1].Replace("+", "%20", StringComparison.Ordinal))
                    : string.Empty,
                StringComparer.Ordinal);
    }

    private sealed class DelayedResponseHandler(TimeSpan delay) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(delay, cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(CreateTokenResponse("fresh-token", "fresh-refresh"))
            };
        }
    }

    private sealed class AdvanceTimeHandler(
        string payload,
        MutableTimeProvider timeProvider,
        TimeSpan advanceBy) : HttpMessageHandler
    {
        private int requestCount;

        public int RequestCount => Volatile.Read(ref requestCount);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref requestCount);
            timeProvider.Advance(advanceBy);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(payload)
            });
        }
    }

    private sealed class CallbackHttpMessageHandler(Func<HttpResponseMessage> responseFactory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(responseFactory());
    }

    private sealed class CompareAndSwapConflictSessionStateStore : IDownstreamUserTokenStore, IOidcSessionStateStore
    {
        private string version = "v1";
        private OidcSessionState state;
        private readonly Queue<OidcSessionState> conflictStates;

        public CompareAndSwapConflictSessionStateStore(
            OidcSessionState initialState,
            IReadOnlyCollection<OidcSessionState> conflictStates)
        {
            state = Clone(initialState);
            this.conflictStates = new Queue<OidcSessionState>(conflictStates.Select(Clone));
        }

        public int CompareAndSwapAttempts { get; private set; }

        public VersionedOidcSessionState CurrentState => new(version, Clone(state));

        public Task<StoredOidcSessionTokenSet?> GetSessionTokenSetAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
            => Task.FromResult(state.SessionTokens is null ? null : Clone(state.SessionTokens));

        public Task StoreSessionTokenSetAsync(ClaimsPrincipal user, StoredOidcSessionTokenSet tokenSet, CancellationToken cancellationToken)
        {
            state.SessionTokens = Clone(tokenSet);
            version = Guid.NewGuid().ToString("n");
            return Task.CompletedTask;
        }

        public Task<CachedDownstreamApiTokenEntry?> GetApiTokenAsync(ClaimsPrincipal user, string downstreamApiName, IReadOnlyCollection<string> scopes, CancellationToken cancellationToken)
        {
            var apiKey = CreateApiKey(downstreamApiName, scopes);
            return Task.FromResult(state.ApiTokens.TryGetValue(apiKey, out var token) ? Clone(token) : null);
        }

        public Task StoreApiTokenAsync(ClaimsPrincipal user, string downstreamApiName, IReadOnlyCollection<string> scopes, CachedDownstreamApiTokenEntry tokenEntry, CancellationToken cancellationToken)
        {
            var apiKey = CreateApiKey(downstreamApiName, scopes);
            state.ApiTokens[apiKey] = Clone(tokenEntry);
            version = Guid.NewGuid().ToString("n");
            return Task.CompletedTask;
        }

        public Task RemoveAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
        {
            state = new OidcSessionState();
            version = Guid.NewGuid().ToString("n");
            return Task.CompletedTask;
        }

        public Task<VersionedOidcSessionState?> GetSessionStateAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
            => Task.FromResult<VersionedOidcSessionState?>(new VersionedOidcSessionState(version, Clone(state)));

        public Task<bool> TryCompareAndSwapSessionStateAsync(ClaimsPrincipal user, string? expectedVersion, OidcSessionState newState, CancellationToken cancellationToken)
        {
            CompareAndSwapAttempts++;
            if (conflictStates.Count > 0)
            {
                state = conflictStates.Dequeue();
                version = Guid.NewGuid().ToString("n");
                return Task.FromResult(false);
            }

            if (!string.Equals(version, expectedVersion, StringComparison.Ordinal))
            {
                return Task.FromResult(false);
            }

            state = Clone(newState);
            version = Guid.NewGuid().ToString("n");
            return Task.FromResult(true);
        }

        public Task DeleteSessionStateAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
            => RemoveAsync(user, cancellationToken);

        private static StoredOidcSessionTokenSet Clone(StoredOidcSessionTokenSet tokenSet)
        {
            return new StoredOidcSessionTokenSet
            {
                RefreshToken = tokenSet.RefreshToken,
                IdToken = tokenSet.IdToken,
                ExpiresAtUtc = tokenSet.ExpiresAtUtc
            };
        }

        private static CachedDownstreamApiTokenEntry Clone(CachedDownstreamApiTokenEntry tokenEntry)
        {
            return new CachedDownstreamApiTokenEntry
            {
                AccessToken = tokenEntry.AccessToken,
                ExpiresAtUtc = tokenEntry.ExpiresAtUtc
            };
        }

        private static OidcSessionState Clone(OidcSessionState source)
        {
            return new OidcSessionState
            {
                SessionTokens = source.SessionTokens is null ? null : Clone(source.SessionTokens),
                ApiTokens = source.ApiTokens.ToDictionary(
                    entry => entry.Key,
                    entry => Clone(entry.Value),
                    StringComparer.Ordinal),
                LastRefreshUtc = source.LastRefreshUtc
            };
        }
    }
}
