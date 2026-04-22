using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal sealed class AuthenticationPrincipalSnapshot
{
    public bool IsAuthenticated { get; init; }

    public string? Name { get; init; }

    public string? PreferredUsername { get; init; }

    public string? Email { get; init; }

    public string? SubjectId { get; init; }

    public string? Issuer { get; init; }

    public string? ObjectId { get; init; }

    public static AuthenticationPrincipalSnapshot FromPrincipal(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var subjectClaim = principal.FindFirst(JwtRegisteredClaimNames.Sub)
            ?? principal.FindFirst(ClaimTypes.NameIdentifier);
        var subjectId = subjectClaim?.Value;
        var issuer = principal.FindFirst(JwtRegisteredClaimNames.Iss)?.Value;

        return new AuthenticationPrincipalSnapshot
        {
            IsAuthenticated = principal.Identity?.IsAuthenticated == true,
            Name = ResolveDisplayName(principal, subjectId),
            PreferredUsername = principal.FindFirst(JwtRegisteredClaimNames.PreferredUsername)?.Value,
            Email = principal.FindFirst(JwtRegisteredClaimNames.Email)?.Value
                ?? principal.FindFirst(ClaimTypes.Email)?.Value,
            SubjectId = subjectId,
            Issuer = issuer,
            ObjectId = principal.FindFirst(OidcAuthenticationConstants.ProviderClaimNames.ObjectId)?.Value
        };
    }

    private static string? ResolveDisplayName(ClaimsPrincipal principal, string? subjectId)
    {
        var identityName = principal.Identity?.Name;
        if (!string.IsNullOrWhiteSpace(identityName))
        {
            return identityName;
        }

        var explicitName = principal.FindFirst(JwtRegisteredClaimNames.Name)?.Value;
        if (!string.IsNullOrWhiteSpace(explicitName))
        {
            return explicitName;
        }

        return subjectId;
    }
}
