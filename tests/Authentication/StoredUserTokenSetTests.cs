using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class StoredOidcSessionTokenSetTests
{
    [Fact]
    public void FromAuthenticationProperties_ReadsTokens()
    {
        var timeProvider = new FixedTimeProvider(DateTimeOffset.Parse("2026-07-31T10:00:00Z"));
        var properties = new AuthenticationProperties();
        properties.StoreTokens(
        [
            new AuthenticationToken { Name = OpenIdConnectParameterNames.RefreshToken, Value = "refresh-1" },
            new AuthenticationToken { Name = OpenIdConnectParameterNames.IdToken, Value = "id-1" },
            new AuthenticationToken { Name = OidcAuthenticationConstants.TokenNames.ExpiresAt, Value = "2030-01-01T00:00:00Z" }
        ]);

        var tokenSet = StoredOidcSessionTokenSet.FromAuthenticationProperties(properties, timeProvider);

        Assert.Equal("refresh-1", tokenSet.RefreshToken);
        Assert.Equal("id-1", tokenSet.IdToken);
        Assert.Equal(DateTimeOffset.Parse("2030-01-01T00:00:00Z"), tokenSet.ExpiresAtUtc);

        var fallbackProperties = new AuthenticationProperties();
        fallbackProperties.StoreTokens(
        [
            new AuthenticationToken { Name = OpenIdConnectParameterNames.RefreshToken, Value = "refresh-2" },
            new AuthenticationToken { Name = OpenIdConnectParameterNames.IdToken, Value = "id-2" }
        ]);

        var fallbackTokenSet = StoredOidcSessionTokenSet.FromAuthenticationProperties(fallbackProperties, timeProvider);

        Assert.Equal("refresh-2", fallbackTokenSet.RefreshToken);
        Assert.Equal("id-2", fallbackTokenSet.IdToken);
        Assert.Equal(timeProvider.GetUtcNow().AddMinutes(5), fallbackTokenSet.ExpiresAtUtc);
    }
}
