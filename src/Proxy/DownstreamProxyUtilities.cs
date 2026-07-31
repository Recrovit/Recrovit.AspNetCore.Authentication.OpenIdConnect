using Microsoft.Extensions.Primitives;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Security.Claims;
using System.Text;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

internal static class DownstreamProxyUtilities
{
    /// <summary>
    /// The only standard request headers forwarded by the downstream proxy.
    /// Headers outside this allowlist, such as <c>Host</c>, <c>Cookie</c>, and other sensitive headers,
    /// are intentionally excluded unless they use the <c>rgf-</c> prefix.
    /// </summary>
    private static readonly HashSet<string> ForwardedHeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Accept",
        "Accept-Language",
        "If-None-Match",
        "If-Modified-Since"
    };

    public static string BuildPathAndQuery(string? prefix, string pathAndQuery)
    {
        var normalizedPathAndQuery = pathAndQuery.TrimStart('/');
        if (string.IsNullOrWhiteSpace(prefix))
        {
            return normalizedPathAndQuery;
        }

        var normalizedPrefix = prefix.Trim('/');
        if (string.IsNullOrEmpty(normalizedPathAndQuery))
        {
            return normalizedPrefix;
        }

        return $"{normalizedPrefix}/{normalizedPathAndQuery}";
    }

    public static void ValidateDownstreamPath(DownstreamApiDefinition downstreamApi, string pathAndQuery)
    {
        _ = CreateValidatedDownstreamUri(downstreamApi, pathAndQuery);
    }

    public static Uri CreateDownstreamUri(DownstreamApiDefinition downstreamApi, string pathAndQuery, bool useWebSocketScheme = false)
    {
        var resolvedUri = CreateValidatedDownstreamUri(downstreamApi, pathAndQuery);
        if (!useWebSocketScheme)
        {
            return resolvedUri;
        }

        var builder = new UriBuilder(resolvedUri)
        {
            Scheme = resolvedUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                ? Uri.UriSchemeWss
                : Uri.UriSchemeWs
        };

        return builder.Uri;
    }

    public static string FormatDownstreamUriForLogging(Uri downstreamUri)
        => FormatPathAndQueryForLogging(downstreamUri.PathAndQuery);

    public static string FormatPathAndQueryForLogging(string pathAndQuery)
    {
        if (string.IsNullOrEmpty(pathAndQuery))
        {
            return "/";
        }

        var queryIndex = pathAndQuery.IndexOf('?');
        var path = queryIndex >= 0 ? pathAndQuery[..queryIndex] : pathAndQuery;
        var query = queryIndex >= 0 ? pathAndQuery[(queryIndex + 1)..] : string.Empty;

        if (string.IsNullOrEmpty(path))
        {
            path = "/";
        }

        if (string.IsNullOrEmpty(query))
        {
            return path;
        }

        var maskedQuery = MaskQueryValues(query);
        return string.IsNullOrEmpty(maskedQuery) ? path : $"{path}?{maskedQuery}";
    }

    public static async Task<string?> TryGetAccessTokenAsync(
        IDownstreamUserTokenProvider tokenProvider,
        ClaimsPrincipal? user,
        string downstreamApiName,
        CancellationToken cancellationToken)
    {
        if (user?.Identity?.IsAuthenticated != true)
        {
            return null;
        }

        return await tokenProvider.GetAccessTokenAsync(user, downstreamApiName, cancellationToken);
    }

    public static void ForwardHeaders(
        IEnumerable<KeyValuePair<string, StringValues>> headers,
        HttpRequestHeaders requestHeaders,
        HttpContentHeaders? contentHeaders)
    {
        foreach (var header in headers)
        {
            if (!ShouldForwardHeader(header.Key))
            {
                continue;
            }

            if (!requestHeaders.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
            {
                contentHeaders?.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }
        }
    }

    public static void ForwardHeaders(
        IEnumerable<KeyValuePair<string, StringValues>> headers,
        ClientWebSocketOptions options)
    {
        foreach (var header in headers)
        {
            if (ShouldForwardHeader(header.Key))
            {
                options.SetRequestHeader(header.Key, string.Join(",", header.Value.ToArray()));
            }
        }
    }

    /// <summary>
    /// Determines whether a request header may be forwarded to a downstream API.
    /// Only the explicit allowlist and custom <c>rgf-*</c> headers are forwarded.
    /// </summary>
    public static bool ShouldForwardHeader(string headerName)
    {
        if (ForwardedHeaderNames.Contains(headerName))
        {
            return true;
        }

        return headerName.StartsWith("rgf-", StringComparison.OrdinalIgnoreCase);
    }

    private static string MaskQueryValues(string query)
    {
        var builder = new StringBuilder(query.Length);
        var start = 0;
        var hasParameter = false;

        while (start <= query.Length)
        {
            var separatorIndex = query.IndexOf('&', start);
            ReadOnlySpan<char> segment = separatorIndex >= 0
                ? query.AsSpan(start, separatorIndex - start)
                : query.AsSpan(start);

            if (!segment.IsEmpty)
            {
                if (hasParameter)
                {
                    builder.Append('&');
                }

                var equalsIndex = segment.IndexOf('=');
                builder.Append(equalsIndex >= 0 ? segment[..equalsIndex] : segment);
                builder.Append("=***");
                hasParameter = true;
            }

            if (separatorIndex < 0)
            {
                break;
            }

            start = separatorIndex + 1;
        }

        return builder.ToString();
    }

    private static Uri CreateValidatedDownstreamUri(DownstreamApiDefinition downstreamApi, string pathAndQuery)
    {
        ValidateIncomingPath(pathAndQuery);

        var baseUri = new Uri(downstreamApi.BaseUrl, UriKind.Absolute);
        var resolvedUri = new Uri(baseUri, BuildPathAndQuery(downstreamApi.RelativePath, pathAndQuery));

        if (!HasMatchingOrigin(baseUri, resolvedUri))
        {
            throw new InvalidDownstreamProxyPathException("The downstream proxy path resolved outside the configured downstream origin.");
        }

        return resolvedUri;
    }

    private static void ValidateIncomingPath(string pathAndQuery)
    {
        var path = GetPathPart(pathAndQuery);
        if (path.Length >= 2 && IsSlashOrBackslash(path[0]) && IsSlashOrBackslash(path[1]))
        {
            throw new InvalidDownstreamProxyPathException("The downstream proxy path must not use an authority-like prefix.");
        }

        var trimmedPath = path.TrimStart('/').ToString();
        if (StartsWithEncodedAuthorityPrefix(trimmedPath))
        {
            throw new InvalidDownstreamProxyPathException("The downstream proxy path must not use an authority-like prefix.");
        }

        if (Uri.TryCreate(trimmedPath, UriKind.Absolute, out _))
        {
            throw new InvalidDownstreamProxyPathException("The downstream proxy path must not be an absolute URI.");
        }
    }

    private static ReadOnlySpan<char> GetPathPart(string pathAndQuery)
    {
        var queryIndex = pathAndQuery.IndexOf('?');
        return queryIndex >= 0
            ? pathAndQuery.AsSpan(0, queryIndex)
            : pathAndQuery.AsSpan();
    }

    private static bool HasMatchingOrigin(Uri expectedOrigin, Uri actualUri)
    {
        return string.Equals(expectedOrigin.Scheme, actualUri.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(expectedOrigin.Host, actualUri.Host, StringComparison.OrdinalIgnoreCase)
            && GetEffectivePort(expectedOrigin) == GetEffectivePort(actualUri);
    }

    private static int GetEffectivePort(Uri uri)
    {
        if (!uri.IsDefaultPort)
        {
            return uri.Port;
        }

        return uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            ? 443
            : uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                ? 80
                : uri.Port;
    }

    private static bool IsSlashOrBackslash(char value) => value is '/' or '\\';

    private static bool StartsWithEncodedAuthorityPrefix(string value)
    {
        return value.StartsWith("%2f%2f", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("%2f%5c", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("%5c%2f", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("%5c%5c", StringComparison.OrdinalIgnoreCase);
    }
}
