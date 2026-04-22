using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal static class UserSubjectIdAccessor
{
    public static string GetRequiredSubjectId(ClaimsPrincipal user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var subjectId = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrWhiteSpace(subjectId))
        {
            throw new InvalidOperationException("No unique subject identifier was found for the authenticated user.");
        }

        return subjectId;
    }
}
