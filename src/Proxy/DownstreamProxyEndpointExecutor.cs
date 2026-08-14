using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

/// <summary>
/// Executes common HTTP proxy endpoint behavior for downstream APIs.
/// </summary>
public static class DownstreamProxyEndpointExecutor
{
    /// <summary>
    /// Proxies the current HTTP request to the specified downstream API and writes the downstream response back to the caller.
    /// </summary>
    public static Task ProxyHttpAsync(
        HttpContext context,
        IDownstreamHttpProxyClient proxyClient,
        string downstreamApiName,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
            => ProxyHttpAsync(
            context,
            proxyClient,
            context.RequestServices.GetRequiredService<DownstreamApiCatalog>(),
            downstreamApiName,
            $"{context.Request.Path}{context.Request.QueryString}",
            user,
            cancellationToken);

    /// <summary>
    /// Proxies the current HTTP request to the specified downstream API path and writes the downstream response back to the caller.
    /// </summary>
    public static async Task ProxyHttpAsync(
        HttpContext context,
        IDownstreamHttpProxyClient proxyClient,
        DownstreamApiCatalog downstreamApiCatalog,
        string downstreamApiName,
        string pathAndQuery,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
    {
        var downstreamApi = downstreamApiCatalog.GetRequired(downstreamApiName);
        var logger = context.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(DownstreamProxyEndpointExecutor).FullName!);
        var endpoint = context.GetEndpoint();
        var endpointMetadata = endpoint?.Metadata.GetMetadata<DownstreamProxyEndpointMetadata>();
        var apiMetadata = endpointMetadata?.GetApiMetadata(downstreamApiName) ?? DownstreamProxyEndpointApiMetadata.Empty;
        var directForwardedRequestHeaders = endpoint?.Metadata
            .GetOrderedMetadata<ForwardedRequestHeadersMetadata>()
            .SelectMany(static metadata => metadata.HeaderNames)
            .ToArray()
            ?? [];
        var forwardedHeaders = DownstreamProxyHeaderPolicy.CreateForwardedRequestHeaders(
            downstreamApi,
            context.Request.Headers,
            user,
            apiMetadata.ForwardedRequestHeaders.Concat(directForwardedRequestHeaders).ToArray(),
            apiMetadata.ClaimHeaderMappings,
            logger);

        using var content = CreateContent(context.Request);
        using var response = await proxyClient.SendAsync(
            downstreamApiName,
            new HttpMethod(context.Request.Method),
            pathAndQuery,
            user,
            content,
            forwardedHeaders,
            cancellationToken);

        await WriteResponseAsync(
            context,
            response,
            downstreamApi,
            downstreamApiName,
            endpointMetadata?.RoutePrefix ?? DownstreamApiProxyEndpointRouteBuilderExtensions.DefaultRoutePrefix,
            logger,
            cancellationToken);
    }

    private static HttpContent? CreateContent(HttpRequest request)
    {
        if (!CanHaveBody(request.Method))
        {
            return null;
        }

        var bodyDetection = request.HttpContext.Features.Get<IHttpRequestBodyDetectionFeature>();
        if (bodyDetection?.CanHaveBody != true)
        {
            return null;
        }

        var content = new StreamContent(request.Body);
        if (!string.IsNullOrWhiteSpace(request.ContentType))
        {
            content.Headers.ContentType = MediaTypeHeaderValue.Parse(request.ContentType);
        }

        CopyContentHeaderIfPresent(request.Headers, content.Headers, "Content-Encoding");
        CopyContentHeaderIfPresent(request.Headers, content.Headers, "Content-Language");

        return content;
    }

    private static bool CanHaveBody(string method)
        => HttpMethods.IsPost(method)
            || HttpMethods.IsPut(method)
            || HttpMethods.IsPatch(method)
            || HttpMethods.IsDelete(method);

    private static void CopyContentHeaderIfPresent(
        IHeaderDictionary requestHeaders,
        HttpContentHeaders contentHeaders,
        string headerName)
    {
        if (!requestHeaders.TryGetValue(headerName, out var values) || values.Count == 0)
        {
            return;
        }

        contentHeaders.TryAddWithoutValidation(headerName, values.ToArray());
    }

    private static async Task WriteResponseAsync(
        HttpContext context,
        HttpResponseMessage response,
        DownstreamApiDefinition downstreamApi,
        string downstreamApiName,
        string routePrefix,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        context.Response.StatusCode = (int)response.StatusCode;
        DownstreamProxyHeaderPolicy.CopyResponseHeaders(context, response, downstreamApi, downstreamApiName, routePrefix, logger);

        await response.Content.CopyToAsync(context.Response.Body, cancellationToken);
    }
}
