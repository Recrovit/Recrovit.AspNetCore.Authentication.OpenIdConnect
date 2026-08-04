using Microsoft.Extensions.Hosting;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

internal static class OidcEndpointHttpsValidator
{
    public static string? GetProductionRequirementError(
        string endpoint,
        bool enforceProductionReadiness,
        string endpointDisplayName)
    {
        if (!enforceProductionReadiness)
        {
            return null;
        }

        return IsAbsoluteHttpsUri(endpoint)
            ? null
            : $"Production-readiness validation requires {endpointDisplayName} to be an absolute HTTPS URI.";
    }

    public static bool IsAbsoluteHttpsUri(string endpoint)
        => Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) &&
            string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
}
