using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Marks endpoints that proxy requests to downstream services and should preserve their original status codes.
/// </summary>
public sealed class ProxyEndpointMetadata
{
    internal static ProxyEndpointMetadata Instance { get; } = new();

    private ProxyEndpointMetadata()
    {
    }
}

/// <summary>
/// Provides endpoint builder extensions for marking proxy endpoints.
/// </summary>
public static class ProxyEndpointConventionBuilderExtensions
{
    /// <summary>
    /// Standard request methods used by basic HTTP proxy endpoints.
    /// </summary>
    public static readonly string[] StandardProxyMethods = [HttpMethods.Get, HttpMethods.Post];

    /// <summary>
    /// Standard request methods used by proxied transport-style endpoints.
    /// </summary>
    public static readonly string[] ProxyTransportMethods = [HttpMethods.Get, HttpMethods.Post, HttpMethods.Delete];

    /// <summary>
    /// General request methods used by generic downstream HTTP proxy endpoints.
    /// </summary>
    public static readonly string[] DownstreamProxyMethods = [HttpMethods.Get, HttpMethods.Post, HttpMethods.Put, HttpMethods.Patch, HttpMethods.Delete];

    /// <summary>
    /// Marks the endpoint or route group as a proxy endpoint.
    /// </summary>
    /// <typeparam name="TBuilder">The endpoint convention builder type.</typeparam>
    /// <param name="builder">The endpoint or route group builder to configure.</param>
    /// <returns>The same endpoint convention builder instance.</returns>
    public static TBuilder AsProxyEndpoint<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.Add(endpointBuilder => endpointBuilder.Metadata.Add(ProxyEndpointMetadata.Instance));
        return builder;
    }
}
