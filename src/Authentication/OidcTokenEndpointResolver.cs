using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal static class OidcTokenEndpointResolver
{
    public static async Task<OidcTokenEndpointResolutionResult> ResolveAsync(
        OpenIdConnectOptions openIdOptions,
        CancellationToken cancellationToken,
        string? directTokenEndpoint = null)
    {
        ArgumentNullException.ThrowIfNull(openIdOptions);

        if (!string.IsNullOrWhiteSpace(directTokenEndpoint))
        {
            return new OidcTokenEndpointResolutionResult(directTokenEndpoint, UsedMetadata: false);
        }

        var staticTokenEndpoint = openIdOptions.Configuration?.TokenEndpoint;
        if (!string.IsNullOrWhiteSpace(staticTokenEndpoint))
        {
            return new OidcTokenEndpointResolutionResult(staticTokenEndpoint, UsedMetadata: false);
        }

        if (openIdOptions.ConfigurationManager is null)
        {
            return new OidcTokenEndpointResolutionResult(null, UsedMetadata: false);
        }

        var configuration = await openIdOptions.ConfigurationManager.GetConfigurationAsync(cancellationToken);
        return new OidcTokenEndpointResolutionResult(configuration.TokenEndpoint, UsedMetadata: true);
    }
}

internal readonly record struct OidcTokenEndpointResolutionResult(string? TokenEndpoint, bool UsedMetadata);
