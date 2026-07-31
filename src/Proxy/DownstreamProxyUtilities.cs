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
        try
        {
            ValidateIncomingPath(pathAndQuery);

            var baseUri = new Uri(downstreamApi.BaseUrl, UriKind.Absolute);
            var resolvedUri = BuildResolvedUri(baseUri, downstreamApi.RelativePath, pathAndQuery);

            ValidateResolvedUri(baseUri, downstreamApi.RelativePath, resolvedUri);
            return resolvedUri;
        }
        catch (InvalidDownstreamProxyPathException)
        {
            throw;
        }
        catch (Exception ex) when (ex is UriFormatException or ArgumentException)
        {
            throw new InvalidDownstreamProxyPathException("The downstream proxy path is malformed.");
        }
    }

    private static void ValidateIncomingPath(string pathAndQuery)
    {
        var path = GetPathPart(pathAndQuery).ToString();
        ValidateAuthorityLikePrefix(path);
        ValidateDecodedPathStages(path);
    }

    private static void ValidateAuthorityLikePrefix(string path)
    {
        if (path.Length >= 2 && IsSlashOrBackslash(path[0]) && IsSlashOrBackslash(path[1]))
        {
            throw new InvalidDownstreamProxyPathException("The downstream proxy path must not use an authority-like prefix.");
        }

        var trimmedPath = path.TrimStart('/');
        if (StartsWithEncodedAuthorityPrefix(trimmedPath))
        {
            throw new InvalidDownstreamProxyPathException("The downstream proxy path must not use an authority-like prefix.");
        }
    }

    private static void ValidateDecodedPathStages(string rawPath)
    {
        var decodedPath = rawPath;

        for (var decodePass = 0; decodePass < 3; decodePass++)
        {
            ValidateAbsoluteUri(decodedPath);
            ValidateDotSegments(decodedPath);

            var nextPath = Uri.UnescapeDataString(decodedPath);
            if (string.Equals(nextPath, decodedPath, StringComparison.Ordinal))
            {
                break;
            }

            ValidateAuthorityLikePrefix(nextPath);
            decodedPath = nextPath;
        }
    }

    private static ReadOnlySpan<char> GetPathPart(string pathAndQuery)
    {
        var queryIndex = pathAndQuery.IndexOf('?');
        return queryIndex >= 0
            ? pathAndQuery.AsSpan(0, queryIndex)
            : pathAndQuery.AsSpan();
    }

    private static string GetQueryPart(string pathAndQuery)
    {
        var queryIndex = pathAndQuery.IndexOf('?');
        if (queryIndex < 0 || queryIndex == pathAndQuery.Length - 1)
        {
            return string.Empty;
        }

        return pathAndQuery[(queryIndex + 1)..];
    }

    private static bool HasMatchingOrigin(Uri expectedOrigin, Uri actualUri)
    {
        return string.Equals(expectedOrigin.Scheme, actualUri.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(expectedOrigin.Host, actualUri.Host, StringComparison.OrdinalIgnoreCase)
            && GetEffectivePort(expectedOrigin) == GetEffectivePort(actualUri);
    }

    private static void ValidateResolvedUri(Uri baseUri, string? relativePath, Uri resolvedUri)
    {
        if (!HasMatchingOrigin(baseUri, resolvedUri))
        {
            throw new InvalidDownstreamProxyPathException("The downstream proxy path resolved outside the configured downstream origin.");
        }

        if (!IsUnderConfiguredRoot(baseUri, relativePath, resolvedUri))
        {
            throw new InvalidDownstreamProxyPathException("The downstream proxy path resolved outside the configured downstream root path.");
        }
    }

    private static bool IsUnderConfiguredRoot(Uri baseUri, string? relativePath, Uri resolvedUri)
    {
        var configuredRootPath = BuildConfiguredRootPath(baseUri.AbsolutePath, relativePath);
        var resolvedPath = NormalizePathForComparison(resolvedUri.AbsolutePath);

        return configuredRootPath == "/"
            || string.Equals(resolvedPath, configuredRootPath, StringComparison.Ordinal)
            || resolvedPath.StartsWith(configuredRootPath + "/", StringComparison.Ordinal);
    }

    private static Uri BuildResolvedUri(Uri baseUri, string? relativePath, string pathAndQuery)
    {
        var builder = new UriBuilder(baseUri)
        {
            Path = BuildCombinedAbsolutePath(baseUri.AbsolutePath, relativePath, GetPathPart(pathAndQuery).ToString()),
            Query = GetQueryPart(pathAndQuery)
        };

        return builder.Uri;
    }

    private static string BuildConfiguredRootPath(string basePath, string? relativePath)
    {
        return NormalizePathForComparison(BuildCombinedAbsolutePath(basePath, relativePath, string.Empty));
    }

    private static string BuildCombinedAbsolutePath(string basePath, string? relativePath, string requestPath)
    {
        var segments = new[]
        {
            basePath,
            relativePath ?? string.Empty,
            requestPath
        };

        var combinedPath = string.Join(
            "/",
            segments
                .SelectMany(static segment => segment.Split('/', StringSplitOptions.RemoveEmptyEntries))
                .Where(static segment => !string.IsNullOrWhiteSpace(segment)));

        return string.IsNullOrEmpty(combinedPath) ? "/" : "/" + combinedPath;
    }

    private static string NormalizePathForComparison(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || string.Equals(path, "/", StringComparison.Ordinal))
        {
            return "/";
        }

        var trimmed = path.TrimEnd('/');
        return trimmed.StartsWith("/") ? trimmed : "/" + trimmed;
    }

    private static void ValidateAbsoluteUri(string path)
    {
        var trimmedPath = path.TrimStart('/');
        if (Uri.TryCreate(trimmedPath, UriKind.Absolute, out _))
        {
            throw new InvalidDownstreamProxyPathException("The downstream proxy path must not be an absolute URI.");
        }
    }

    private static void ValidateDotSegments(string path)
    {
        var normalizedPath = path.Replace('\\', '/');
        foreach (var segment in normalizedPath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment is "." or "..")
            {
                throw new InvalidDownstreamProxyPathException("The downstream proxy path must not contain dot-segment traversal.");
            }
        }
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
