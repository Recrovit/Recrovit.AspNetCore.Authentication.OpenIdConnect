using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

/// <summary>
/// Maps generic proxy endpoints for configured downstream APIs.
/// </summary>
public static class DownstreamApiProxyEndpointRouteBuilderExtensions
{
    public const string DefaultRoutePrefix = "/downstream";

    public static IEndpointRouteBuilder MapDownstreamApiProxyEndpoints(this IEndpointRouteBuilder endpoints, string routePrefix = DefaultRoutePrefix)
    {
        var normalizedRoutePrefix = NormalizeRoutePrefix(routePrefix);

        endpoints.MapMethods(
                $"{normalizedRoutePrefix}/{{apiName}}",
                ProxyEndpointConventionBuilderExtensions.DownstreamProxyMethods,
                ProxyDownstreamApiAsync)
            .AsProxyEndpoint()
            .RequireAuthorization()
            .DisableAuthRedirects()
            .WithSummary("Proxies requests to a configured downstream API.");

        endpoints.MapMethods(
                $"{normalizedRoutePrefix}/{{apiName}}/{{**path}}",
                ProxyEndpointConventionBuilderExtensions.DownstreamProxyMethods,
                ProxyDownstreamApiAsync)
            .AsProxyEndpoint()
            .RequireAuthorization()
            .DisableAuthRedirects()
            .WithSummary("Proxies requests to a configured downstream API.");

        return endpoints;
    }

    private static async Task<IResult> ProxyDownstreamApiAsync(
        HttpContext context,
        string apiName,
        string? path,
        DownstreamApiCatalog downstreamApiCatalog,
        IDownstreamHttpProxyClient httpProxyClient,
        IDownstreamTransportProxyClient transportProxyClient,
        CancellationToken cancellationToken)
    {
        if (!downstreamApiCatalog.Apis.ContainsKey(apiName))
        {
            return Results.NotFound();
        }

        var pathAndQuery = BuildPathAndQuery(path, context.Request.QueryString);

        if (context.WebSockets.IsWebSocketRequest)
        {
            await transportProxyClient.ProxyWebSocketAsync(context, apiName, pathAndQuery, context.User, cancellationToken);
            return Results.Empty;
        }

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            httpProxyClient,
            apiName,
            pathAndQuery,
            context.User,
            cancellationToken);

        return Results.Empty;
    }

    private static string NormalizeRoutePrefix(string routePrefix)
    {
        var normalized = string.IsNullOrWhiteSpace(routePrefix)
            ? DefaultRoutePrefix
            : routePrefix.Trim();

        if (!normalized.StartsWith('/'))
        {
            normalized = "/" + normalized;
        }

        return normalized.TrimEnd('/');
    }

    private static string BuildPathAndQuery(string? path, QueryString queryString)
    {
        var normalizedPath = string.IsNullOrWhiteSpace(path)
            ? string.Empty
            : "/" + path.TrimStart('/');

        return $"{normalizedPath}{queryString}";
    }
}
