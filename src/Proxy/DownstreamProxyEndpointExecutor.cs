using Microsoft.AspNetCore.Http;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

/// <summary>
/// Executes common HTTP proxy endpoint behavior for downstream APIs.
/// </summary>
public static class DownstreamProxyEndpointExecutor
{
    private static readonly HashSet<string> BlockedResponseHeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "Set-Cookie",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade"
    };

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
        var additionalBlockedHeaders = GetConnectionDeclaredHeaders(response.Headers);

        foreach (var header in response.Headers)
        {
            if (ShouldCopyResponseHeader(header.Key, additionalBlockedHeaders))
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
        }

        foreach (var header in response.Content.Headers)
        {
            if (ShouldCopyResponseHeader(header.Key, additionalBlockedHeaders))
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
        }

        context.Response.Headers.Remove("transfer-encoding");

        await response.Content.CopyToAsync(context.Response.Body, cancellationToken);
    }

    private static bool ShouldCopyResponseHeader(string headerName, HashSet<string> additionalBlockedHeaders)
        => !BlockedResponseHeaderNames.Contains(headerName) && !additionalBlockedHeaders.Contains(headerName);

    private static HashSet<string> GetConnectionDeclaredHeaders(HttpResponseHeaders headers)
    {
        var blockedHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var headerValue in headers.Connection)
        {
            if (string.IsNullOrWhiteSpace(headerValue))
            {
                continue;
            }

            blockedHeaders.Add(headerValue.Trim());
        }

        if (!headers.TryGetValues("Connection", out var rawValues))
        {
            return blockedHeaders;
        }

        foreach (var rawValue in rawValues)
        {
            foreach (var token in rawValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                blockedHeaders.Add(token);
            }
        }

        return blockedHeaders;
    }
}
