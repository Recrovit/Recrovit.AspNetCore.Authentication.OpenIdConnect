using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
    public async Task GetAccessTokenAsync_ThrowsReauthenticationRequired_WhenRefreshFailsWithInvalidGrant()
    {
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
        InMemoryTokenStore tokenStore,
        IHttpClientFactory httpClientFactory,
        FakeWebHostEnvironment? environment = null,
        ListLoggerFactory? loggerFactory = null,
        IOptionsMonitor<OpenIdConnectOptions>? openIdOptionsMonitor = null)
    {
        var services = new ServiceCollection();
        environment ??= new FakeWebHostEnvironment { EnvironmentName = Environments.Development };
        services.AddLogging();
        services.AddOidcAuthenticationInfrastructure(TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:BaseUrl"] = "https://api.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:Scopes:0"] = "openid",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:GraphApi:BaseUrl"] = "https://graph.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:GraphApi:Scopes:0"] = "graph.read"
        }), environment);
        services.Replace(ServiceDescriptor.Scoped<IDownstreamUserTokenStore>(_ => tokenStore));
        services.Replace(ServiceDescriptor.Singleton(httpClientFactory));
        services.Replace(ServiceDescriptor.Singleton<IOptionsMonitor<OpenIdConnectOptions>>(openIdOptionsMonitor ?? new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
        {
            ConfigurationManager = new StaticConfigurationManager("https://idp.example.com/connect/token")
        })));

        if (loggerFactory is not null)
        {
            services.Replace(ServiceDescriptor.Singleton<ILoggerFactory>(loggerFactory));
        }

        var serviceProvider = services.BuildServiceProvider();
        return serviceProvider.GetRequiredService<IDownstreamUserTokenProvider>();
    }

    private static string CreateJwtAccessToken((string Name, string Value) claim)
        => CreateJwtAccessToken([claim]);

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
}
