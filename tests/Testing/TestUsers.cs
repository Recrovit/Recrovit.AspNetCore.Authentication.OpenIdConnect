using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;

internal static class TestUsers
{
    public static ClaimsPrincipal CreateAuthenticatedUser(
        string subjectId = "user-123",
        string issuer = "https://idp.example.com",
        bool includeIssuerClaim = true,
        string sessionId = "session-123")
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subjectId, ClaimValueTypes.String, issuer),
            new(OidcAuthenticationConstants.ProviderClaimNames.LocalSessionId, sessionId)
        };
        if (includeIssuerClaim)
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Iss, issuer));
        }

        return CreateAuthenticatedUser(claims);
    }

    public static ClaimsPrincipal CreateAuthenticatedUser(IEnumerable<Claim> claims, string? nameClaimType = null)
    {
        var claimList = claims.ToList();
        if (!claimList.Any(static claim => claim.Type == OidcAuthenticationConstants.ProviderClaimNames.LocalSessionId))
        {
            claimList.Add(new Claim(OidcAuthenticationConstants.ProviderClaimNames.LocalSessionId, "session-123"));
        }

        var identity = nameClaimType is null
            ? new ClaimsIdentity(claimList, "test")
            : new ClaimsIdentity(claimList, "test", nameClaimType, ClaimTypes.Role);

        return new ClaimsPrincipal(identity);
    }
}
