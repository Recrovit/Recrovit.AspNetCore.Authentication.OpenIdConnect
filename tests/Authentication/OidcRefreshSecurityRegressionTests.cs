using System.Net;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
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
}
