using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Provides endpoint registration extensions for reusable OIDC authentication routes.
/// </summary>
public static class OidcAuthenticationEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the reusable login, logout, and session endpoints for the configured OIDC host.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder used to register the authentication endpoints.</param>
    /// <returns>The same endpoint route builder instance.</returns>
    public static IEndpointRouteBuilder MapOidcAuthenticationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var authOptions = endpoints.ServiceProvider.GetRequiredService<IOptions<OidcAuthenticationOptions>>().Value;
        AuthenticationEndpoints.MapLoginLogoutAndSessionEndpoints(endpoints, authOptions);
        return endpoints;
    }
}
