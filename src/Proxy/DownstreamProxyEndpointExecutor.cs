using Microsoft.AspNetCore.Http;
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
        string downstreamApiName,
        string pathAndQuery,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
    {
        using var content = CreateContent(context.Request);
        using var response = await proxyClient.SendAsync(
            downstreamApiName,
            new HttpMethod(context.Request.Method),
            pathAndQuery,
            user,
            content,
            context.Request.Headers,
            cancellationToken);

        await WriteResponseAsync(context, response, cancellationToken);
    }

    private static HttpContent? CreateContent(HttpRequest request)
    {
        if (!CanHaveBody(request.Method) || request.ContentLength is null or 0)
        {
            return null;
        }

        var content = new StreamContent(request.Body);
        if (!string.IsNullOrWhiteSpace(request.ContentType))
        {
            content.Headers.ContentType = MediaTypeHeaderValue.Parse(request.ContentType);
        }

        return content;
    }

    private static bool CanHaveBody(string method)
        => HttpMethods.IsPost(method)
            || HttpMethods.IsPut(method)
            || HttpMethods.IsPatch(method)
            || HttpMethods.IsDelete(method);

    private static async Task WriteResponseAsync(HttpContext context, HttpResponseMessage response, CancellationToken cancellationToken)
    {
        context.Response.StatusCode = (int)response.StatusCode;

        foreach (var header in response.Headers)
        {
            if (ShouldCopyHeader(header.Key))
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
        }

        foreach (var header in response.Content.Headers)
        {
            if (ShouldCopyHeader(header.Key))
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
        }

        context.Response.Headers.Remove("transfer-encoding");

        await response.Content.CopyToAsync(context.Response.Body, cancellationToken);
    }

    private static bool ShouldCopyHeader(string headerName) =>
        !headerName.Equals("transfer-encoding", StringComparison.OrdinalIgnoreCase);
}
