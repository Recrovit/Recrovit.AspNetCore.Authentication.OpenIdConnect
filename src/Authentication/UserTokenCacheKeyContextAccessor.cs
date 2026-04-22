using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal sealed class UserTokenCacheKeyContextAccessor(IOptions<ActiveOidcProviderOptions> activeProviderOptions)
{
    public UserTokenCacheKeyContext GetRequiredContext(ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var subjectClaim = user.FindFirst(JwtRegisteredClaimNames.Sub) ?? user.FindFirst(ClaimTypes.NameIdentifier);
        var subjectId = subjectClaim?.Value;
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            throw new InvalidOperationException("No unique subject identifier was found for the authenticated user.");
        }

        var issuer = user.FindFirst(JwtRegisteredClaimNames.Iss)?.Value;
        if (string.IsNullOrWhiteSpace(issuer))
        {
            var subjectClaimIssuer = subjectClaim?.Issuer;
            if (!string.IsNullOrWhiteSpace(subjectClaimIssuer) &&
                !string.Equals(subjectClaimIssuer, ClaimsIdentity.DefaultIssuer, StringComparison.Ordinal))
            {
                issuer = subjectClaimIssuer;
            }
        }

        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new InvalidOperationException("No issuer identifier was found for the authenticated user.");
        }

        var sessionId = user.FindFirst(OidcAuthenticationConstants.ProviderClaimNames.LocalSessionId)?.Value;
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            throw new InvalidOperationException("No local session identifier was found for the authenticated user.");
        }

        return new UserTokenCacheKeyContext(activeProviderOptions.Value.ProviderName, issuer, subjectId, sessionId);
    }
}
