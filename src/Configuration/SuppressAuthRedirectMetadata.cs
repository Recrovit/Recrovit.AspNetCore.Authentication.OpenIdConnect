using Microsoft.AspNetCore.Builder;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Marks endpoints that should return HTTP status codes instead of redirecting to the login flow.
/// </summary>
public sealed class SuppressAuthRedirectMetadata
{
    internal static SuppressAuthRedirectMetadata Instance { get; } = new();

    private SuppressAuthRedirectMetadata()
    {
    }
}

/// <summary>
/// Provides endpoint builder extensions for suppressing authentication redirects on API-like endpoints.
/// </summary>
public static class SuppressAuthRedirectEndpointConventionBuilderExtensions
{
    /// <summary>
    /// Configures the endpoint or route group to return <c>401</c> or <c>403</c> instead of redirecting to the login flow.
    /// </summary>
    /// <typeparam name="TBuilder">The endpoint convention builder type.</typeparam>
    /// <param name="builder">The endpoint or route group builder to configure.</param>
    /// <returns>The same endpoint convention builder instance.</returns>
    public static TBuilder DisableAuthRedirects<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.Add(endpointBuilder => endpointBuilder.Metadata.Add(SuppressAuthRedirectMetadata.Instance));
        return builder;
    }
}
