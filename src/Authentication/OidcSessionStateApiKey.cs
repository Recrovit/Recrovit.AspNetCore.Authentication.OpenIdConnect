using System.Security.Cryptography;
using System.Text;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal static class OidcSessionStateApiKey
{
    public static string Create(string downstreamApiName, IReadOnlyCollection<string> scopes)
    {
        var normalizedScopes = OidcScopeResolver.NormalizeScopes(scopes);
        var serializedScopes = string.Join(" ", normalizedScopes);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(serializedScopes));
        return $"{downstreamApiName}:{Convert.ToHexString(hash)}";
    }
}
