using System.Net;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class OidcRefreshSecurityRegressionTests
{
    [Fact]
    public async Task GetAccessTokenAsync_ThrowsReauthenticationRequired_WhenRefreshTokenMissing()
    {
        var provider = TestFactories.CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = null,
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(-30)
            }),
            new StubHttpClientFactory("{}"));

        var ex = await Assert.ThrowsAsync<OidcReauthenticationRequiredException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));

        Assert.Contains("refresh token", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ThrowsReauthenticationRequired_WhenRefreshResponseOmitsAccessToken()
    {
        var provider = TestFactories.CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(-30)
            }),
            new StubHttpClientFactory("""{"refresh_token":"fresh-refresh"}""", HttpStatusCode.OK));

        var ex = await Assert.ThrowsAsync<OidcReauthenticationRequiredException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));

        Assert.Contains("did not contain an access token", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetAccessTokenAsync_ThrowsTokenRefreshFailed_WhenRefreshTransportFails()
    {
        var provider = TestFactories.CreateProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(-30)
            }),
            new DelegatingHttpClientFactory(new ThrowingHttpMessageHandler(new HttpRequestException("network down"))));

        var ex = await Assert.ThrowsAsync<OidcTokenRefreshFailedException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));

        Assert.Contains("transport error", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(HttpStatusCode.MovedPermanently, OidcClientAuthenticationMethod.ClientSecretPost)]
    [InlineData(HttpStatusCode.Found, OidcClientAuthenticationMethod.ClientSecretPost)]
    [InlineData(HttpStatusCode.SeeOther, OidcClientAuthenticationMethod.ClientSecretPost)]
    [InlineData(HttpStatusCode.TemporaryRedirect, OidcClientAuthenticationMethod.ClientSecretPost)]
    [InlineData(HttpStatusCode.PermanentRedirect, OidcClientAuthenticationMethod.ClientSecretPost)]
    [InlineData(HttpStatusCode.MovedPermanently, OidcClientAuthenticationMethod.PrivateKeyJwt)]
    [InlineData(HttpStatusCode.Found, OidcClientAuthenticationMethod.PrivateKeyJwt)]
    [InlineData(HttpStatusCode.SeeOther, OidcClientAuthenticationMethod.PrivateKeyJwt)]
    [InlineData(HttpStatusCode.TemporaryRedirect, OidcClientAuthenticationMethod.PrivateKeyJwt)]
    [InlineData(HttpStatusCode.PermanentRedirect, OidcClientAuthenticationMethod.PrivateKeyJwt)]
    public async Task GetAccessTokenAsync_DoesNotFollowRedirectResponses_FromTokenEndpoint(
        HttpStatusCode redirectStatusCode,
        OidcClientAuthenticationMethod clientAuthenticationMethod)
    {
        const string tokenEndpointPath = "/connect/token";
        const string redirectTargetPath = "/redirect-target";
        Uri? redirectTargetUri = null;

        await using var server = await LoopbackHttpServer.StartAsync((request, _) =>
        {
            if (string.Equals(request.Path, tokenEndpointPath, StringComparison.Ordinal))
            {
                return Task.FromResult(new LoopbackHttpResponse(
                    redirectStatusCode,
                    ResponseHeaders: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Location"] = redirectTargetUri!.AbsoluteUri
                    }));
            }

            return Task.FromResult(new LoopbackHttpResponse(HttpStatusCode.OK, """{"access_token":"redirected-token","expires_in":120}"""));
        });
        redirectTargetUri = new Uri(server.BaseAddress, redirectTargetPath);

        var provider = CreateDirectProvider(
            new InMemoryTokenStore(new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(-30)
            }),
            new RecordingHttpClientFactory(_ => new HttpClient(new HttpClientHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false
            })
            {
                Timeout = TimeSpan.FromSeconds(5)
            }),
            tokenEndpoint: new Uri(server.BaseAddress, tokenEndpointPath),
            clientAuthenticationMethod: clientAuthenticationMethod);

        var ex = await Assert.ThrowsAsync<OidcTokenRefreshFailedException>(() =>
            provider.GetAccessTokenAsync(TestUsers.CreateAuthenticatedUser(), "SessionValidationApi", CancellationToken.None));

        Assert.Contains("redirect responses are not allowed", ex.Message, StringComparison.OrdinalIgnoreCase);

        var requests = server.Requests.ToArray();
        var tokenRequests = requests.Where(request => string.Equals(request.Path, tokenEndpointPath, StringComparison.Ordinal)).ToArray();
        var redirectRequests = requests.Where(request => string.Equals(request.Path, redirectTargetPath, StringComparison.Ordinal)).ToArray();

        Assert.Single(tokenRequests);
        Assert.Empty(redirectRequests);

        var tokenRequestBody = tokenRequests[0].Body;
        Assert.Contains("refresh_token=refresh-token", tokenRequestBody, StringComparison.Ordinal);
        if (clientAuthenticationMethod == OidcClientAuthenticationMethod.ClientSecretPost)
        {
            Assert.Contains("client_secret=client-secret", tokenRequestBody, StringComparison.Ordinal);
            Assert.DoesNotContain("client_assertion=", tokenRequestBody, StringComparison.Ordinal);
        }
        else
        {
            Assert.Contains("client_assertion=redirect-client-assertion", tokenRequestBody, StringComparison.Ordinal);
            Assert.DoesNotContain("client_secret=", tokenRequestBody, StringComparison.Ordinal);
        }
    }

    private static OidcDownstreamUserTokenProvider CreateDirectProvider(
        InMemoryTokenStore tokenStore,
        IHttpClientFactory httpClientFactory,
        Uri tokenEndpoint,
        OidcClientAuthenticationMethod clientAuthenticationMethod)
    {
        var oidcOptions = new OidcProviderOptions
        {
            Authority = "https://idp.example.com",
            ClientId = "client-id",
            ClientSecret = clientAuthenticationMethod == OidcClientAuthenticationMethod.ClientSecretPost
                ? "client-secret"
                : null,
            ClientAuthenticationMethod = clientAuthenticationMethod,
            Scopes = ["openid"],
            TokenEndpointTimeout = TimeSpan.FromSeconds(5)
        };

        return new OidcDownstreamUserTokenProvider(
            tokenStore,
            TestFactories.CreateDownstreamApiCatalog(),
            Options.Create(oidcOptions),
            Options.Create(new ActiveOidcProviderOptions { ProviderName = "Duende" }),
            Options.Create(TestFactories.CreateTokenCacheOptions()),
            new LoggerFactory().CreateLogger<OidcDownstreamUserTokenProvider>(),
            httpClientFactory,
            new FakeHostEnvironment { EnvironmentName = Environments.Development },
            new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
            {
                Configuration = new OpenIdConnectConfiguration
                {
                    TokenEndpoint = tokenEndpoint.AbsoluteUri
                },
                ConfigurationManager = null
            }),
            clientAuthenticationMethod == OidcClientAuthenticationMethod.PrivateKeyJwt
                ? new FixedClientAssertionService("redirect-client-assertion")
                : null);
    }
}
