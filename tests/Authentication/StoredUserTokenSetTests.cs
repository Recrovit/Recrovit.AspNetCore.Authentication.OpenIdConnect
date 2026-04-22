using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class StoredOidcSessionTokenSetTests
{
    [Fact]
    public void FromAuthenticationProperties_ReadsTokens()
    {
        var properties = new AuthenticationProperties();
        properties.StoreTokens(
        [
            new AuthenticationToken { Name = OpenIdConnectParameterNames.RefreshToken, Value = "refresh-1" },
            new AuthenticationToken { Name = OpenIdConnectParameterNames.IdToken, Value = "id-1" },
            new AuthenticationToken { Name = OidcAuthenticationConstants.TokenNames.ExpiresAt, Value = "2030-01-01T00:00:00Z" }
        ]);

        var tokenSet = StoredOidcSessionTokenSet.FromAuthenticationProperties(properties);

        Assert.Equal("refresh-1", tokenSet.RefreshToken);
        Assert.Equal("id-1", tokenSet.IdToken);
        Assert.Equal(DateTimeOffset.Parse("2030-01-01T00:00:00Z"), tokenSet.ExpiresAtUtc);
    }
}
