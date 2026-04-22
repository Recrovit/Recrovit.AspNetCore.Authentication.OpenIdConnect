using Microsoft.Extensions.Hosting;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

internal static class OidcEndpointHttpsValidator
{
    public static string? GetProductionRequirementError(string endpoint, IHostEnvironment environment, string endpointDisplayName)
    {
        if (!environment.IsProduction())
        {
            return null;
        }

        return Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) &&
            string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            ? null
            : $"Production requires {endpointDisplayName} to be an absolute HTTPS URI.";
    }
}
