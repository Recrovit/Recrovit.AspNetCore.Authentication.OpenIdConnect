using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

internal static class DownstreamProxyHeaderPolicy
{
    private static readonly HashSet<string> DefaultForwardedRequestHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Accept",
        "Accept-Language",
        "If-Modified-Since",
        "If-None-Match"
    };

    private static readonly HashSet<string> DefaultForwardedResponseHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Accept-Ranges",
        "Cache-Control",
        "Content-Disposition",
        "Content-Encoding",
        "Content-Language",
        "Content-Length",
        "Content-Range",
        "Content-Type",
        "ETag",
        "Expires",
        "Last-Modified",
        "Retry-After",
        "Vary"
    };

    private static readonly HashSet<string> HopByHopHeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade"
    };

    private static readonly HashSet<string> AlwaysBlockedRequestHeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization",
        "Cookie",
        "Content-Length",
        "Forwarded",
        "Host",
        "Proxy-Authorization"
    };

    private static readonly HashSet<string> AlwaysBlockedResponseHeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Alt-Svc",
        "Clear-Site-Data",
        "Content-Security-Policy",
        "Content-Security-Policy-Report-Only",
        "Location",
        "NEL",
        "Origin-Agent-Cluster",
        "Permissions-Policy",
        "Referrer-Policy",
        "Refresh",
        "Report-To",
        "Reporting-Endpoints",
        "Set-Cookie",
        "Set-Cookie2",
        "Strict-Transport-Security",
        "Timing-Allow-Origin",
        "X-Content-Type-Options",
        "X-Frame-Options"
    };

    public static void ValidateConfiguredRequestHeaderName(string headerName, string configurationPath)
    {
        ValidateHeaderName(headerName, configurationPath);

        if (IsBlockedRequestHeader(headerName))
        {
            throw new InvalidOperationException($"{configurationPath} contains forbidden request header '{headerName}'.");
        }
    }

    public static void ValidateGeneratedRequestHeaderName(string headerName, string configurationPath)
    {
        ValidateConfiguredRequestHeaderName(headerName, configurationPath);
    }

    public static void ValidateConfiguredResponseHeaderName(string headerName, string configurationPath)
    {
        ValidateHeaderName(headerName, configurationPath);

        if (IsBlockedResponseHeader(headerName))
        {
            throw new InvalidOperationException($"{configurationPath} contains forbidden response header '{headerName}'.");
        }
    }

    public static IReadOnlyList<KeyValuePair<string, StringValues>> CreateForwardedRequestHeaders(
        DownstreamApiDefinition downstreamApi,
        IEnumerable<KeyValuePair<string, StringValues>> incomingHeaders,
        ClaimsPrincipal? user,
        IReadOnlyList<DownstreamProxyClaimHeaderMapping> claimHeaderMappings,
        ILogger logger)
    {
        var allowedHeaders = downstreamApi.IncludeDefaultForwardedRequestHeaders
            ? new HashSet<string>(DefaultForwardedRequestHeaders, StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        allowedHeaders.UnionWith(downstreamApi.ForwardedRequestHeaders);
        var protectedHeaderNames = new HashSet<string>(
            claimHeaderMappings.Select(static mapping => mapping.HeaderName),
            StringComparer.OrdinalIgnoreCase);
        var connectionDeclaredHeaders = GetConnectionDeclaredHeaders(incomingHeaders);
        var forwardedHeaders = new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase);

        foreach (var header in incomingHeaders)
        {
            if (protectedHeaderNames.Contains(header.Key))
            {
                LogDroppedHeader(logger, "request", header.Key, "protected-claim-header");
                continue;
            }

            if (!allowedHeaders.Contains(header.Key))
            {
                LogDroppedHeader(logger, "request", header.Key, "not-allowlisted");
                continue;
            }

            if (IsBlockedRequestHeader(header.Key) || connectionDeclaredHeaders.Contains(header.Key))
            {
                LogDroppedHeader(logger, "request", header.Key, "forbidden");
                continue;
            }

            forwardedHeaders[header.Key] = FilterValues(header.Value);
        }

        foreach (var mapping in claimHeaderMappings)
        {
            var values = mapping.ForwardAllValues
                ? GetAllClaimValues(user, mapping.ClaimTypes)
                : GetFirstClaimValue(user, mapping.ClaimTypes);
            if (values.Count == 0)
            {
                continue;
            }

            forwardedHeaders[mapping.HeaderName] = new StringValues(values.ToArray());
        }

        return forwardedHeaders
            .Where(static header => header.Value.Count > 0)
            .Select(static header => new KeyValuePair<string, StringValues>(header.Key, header.Value))
            .ToArray();
    }

    public static void CopyResponseHeaders(
        HttpContext context,
        HttpResponseMessage downstreamResponse,
        DownstreamApiDefinition downstreamApi,
        string downstreamApiName,
        string routePrefix,
        ILogger logger)
    {
        var allowedHeaders = new HashSet<string>(DefaultForwardedResponseHeaders, StringComparer.OrdinalIgnoreCase);
        allowedHeaders.UnionWith(downstreamApi.ForwardedResponseHeaders);

        var connectionDeclaredHeaders = GetConnectionDeclaredHeaders(downstreamResponse.Headers);

        foreach (var header in downstreamResponse.Headers)
        {
            CopyResponseHeader(context, downstreamResponse, downstreamApi, downstreamApiName, routePrefix, logger, allowedHeaders, connectionDeclaredHeaders, header.Key, header.Value);
        }

        foreach (var header in downstreamResponse.Content.Headers)
        {
            CopyResponseHeader(context, downstreamResponse, downstreamApi, downstreamApiName, routePrefix, logger, allowedHeaders, connectionDeclaredHeaders, header.Key, header.Value);
        }

        context.Response.Headers.Remove("transfer-encoding");
    }

    private static void CopyResponseHeader(
        HttpContext context,
        HttpResponseMessage downstreamResponse,
        DownstreamApiDefinition downstreamApi,
        string downstreamApiName,
        string routePrefix,
        ILogger logger,
        HashSet<string> allowedHeaders,
        HashSet<string> connectionDeclaredHeaders,
        string headerName,
        IEnumerable<string> values)
    {
        if (string.Equals(headerName, "Location", StringComparison.OrdinalIgnoreCase))
        {
            var locationValue = values.LastOrDefault();
            if (string.IsNullOrWhiteSpace(locationValue))
            {
                LogDroppedHeader(logger, "response", headerName, "empty");
                return;
            }

            if (!TryRewriteLocation(downstreamResponse.RequestMessage?.RequestUri, downstreamApi, downstreamApiName, routePrefix, locationValue, out var rewrittenLocation, out var reason))
            {
                LogDroppedHeader(logger, "redirect", headerName, reason);
                return;
            }

            context.Response.Headers[headerName] = rewrittenLocation;
            return;
        }

        if (!allowedHeaders.Contains(headerName))
        {
            LogDroppedHeader(logger, "response", headerName, "not-allowlisted");
            return;
        }

        if (IsBlockedResponseHeader(headerName) || connectionDeclaredHeaders.Contains(headerName))
        {
            LogDroppedHeader(logger, "response", headerName, "forbidden");
            return;
        }

        context.Response.Headers[headerName] = values.ToArray();
    }

    private static bool TryRewriteLocation(
        Uri? downstreamRequestUri,
        DownstreamApiDefinition downstreamApi,
        string downstreamApiName,
        string routePrefix,
        string locationValue,
        out string rewrittenLocation,
        out string reason)
    {
        rewrittenLocation = string.Empty;
        reason = string.Empty;

        try
        {
            var configuredBaseUri = new Uri(downstreamApi.BaseUrl, UriKind.Absolute);
            var resolutionBase = downstreamRequestUri ?? configuredBaseUri;
            var resolvedUri = Uri.TryCreate(locationValue, UriKind.Absolute, out var absoluteLocation)
                ? absoluteLocation
                : new Uri(resolutionBase, locationValue);

            if (!DownstreamProxyUtilities.HasMatchingOrigin(configuredBaseUri, resolvedUri))
            {
                reason = "external-origin";
                return false;
            }

            if (!DownstreamProxyUtilities.IsUnderConfiguredRoot(configuredBaseUri, downstreamApi.RelativePath, resolvedUri))
            {
                reason = "outside-root";
                return false;
            }

            var configuredRoot = DownstreamProxyUtilities.BuildConfiguredRootPath(configuredBaseUri.AbsolutePath, downstreamApi.RelativePath);
            var resolvedPath = DownstreamProxyUtilities.NormalizePathForComparison(resolvedUri.AbsolutePath);
            var suffix = string.Equals(resolvedPath, configuredRoot, StringComparison.Ordinal)
                ? string.Empty
                : resolvedPath[configuredRoot.Length..];
            var normalizedRoutePrefix = routePrefix.TrimEnd('/');
            var publicPath = $"{normalizedRoutePrefix}/{downstreamApiName}{suffix}";
            rewrittenLocation = $"{publicPath}{resolvedUri.Query}{resolvedUri.Fragment}";
            return true;
        }
        catch (Exception ex) when (ex is UriFormatException or InvalidOperationException or ArgumentException)
        {
            reason = "invalid-location";
            return false;
        }
    }

    private static bool IsBlockedRequestHeader(string headerName)
        => AlwaysBlockedRequestHeaderNames.Contains(headerName)
            || HopByHopHeaderNames.Contains(headerName)
            || headerName.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase)
            || string.Equals(headerName, "X-Real-IP", StringComparison.OrdinalIgnoreCase);

    private static bool IsBlockedResponseHeader(string headerName)
        => AlwaysBlockedResponseHeaderNames.Contains(headerName)
            || HopByHopHeaderNames.Contains(headerName)
            || headerName.StartsWith("Access-Control-", StringComparison.OrdinalIgnoreCase)
            || headerName.StartsWith("Cross-Origin-", StringComparison.OrdinalIgnoreCase);

    private static void ValidateHeaderName(string headerName, string configurationPath)
    {
        if (string.IsNullOrWhiteSpace(headerName))
        {
            throw new InvalidOperationException($"{configurationPath} contains an empty header name.");
        }

        foreach (var character in headerName)
        {
            if (!IsTokenCharacter(character))
            {
                throw new InvalidOperationException($"{configurationPath} contains invalid header name '{headerName}'.");
            }
        }
    }

    private static bool IsTokenCharacter(char character)
        => char.IsAsciiLetterOrDigit(character)
            || character is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';

    private static StringValues FilterValues(StringValues values)
    {
        if (values.Count == 0)
        {
            return StringValues.Empty;
        }

        var filtered = values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return filtered.Length == 0 ? StringValues.Empty : new StringValues(filtered);
    }

    private static IReadOnlyList<string> GetFirstClaimValue(ClaimsPrincipal? user, IReadOnlyList<string> claimTypes)
    {
        if (user is null)
        {
            return [];
        }

        foreach (var claimType in claimTypes)
        {
            var value = user.FindFirst(claimType)?.Value;
            if (!string.IsNullOrWhiteSpace(value))
            {
                return [value];
            }
        }

        return [];
    }

    private static IReadOnlyList<string> GetAllClaimValues(ClaimsPrincipal? user, IReadOnlyList<string> claimTypes)
    {
        if (user is null)
        {
            return [];
        }

        return claimTypes
            .SelectMany(user.FindAll)
            .Select(static claim => claim.Value)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static HashSet<string> GetConnectionDeclaredHeaders(IEnumerable<KeyValuePair<string, StringValues>> headers)
    {
        var blockedHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var header in headers.Where(static header => string.Equals(header.Key, "Connection", StringComparison.OrdinalIgnoreCase)))
        {
            foreach (var value in header.Value)
            {
                AddConnectionDeclaredHeaders(blockedHeaders, value);
            }
        }

        return blockedHeaders;
    }

    private static HashSet<string> GetConnectionDeclaredHeaders(HttpResponseHeaders headers)
    {
        var blockedHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var value in headers.Connection)
        {
            AddConnectionDeclaredHeaders(blockedHeaders, value);
        }

        if (headers.TryGetValues("Connection", out var rawValues))
        {
            foreach (var value in rawValues)
            {
                AddConnectionDeclaredHeaders(blockedHeaders, value);
            }
        }

        return blockedHeaders;
    }

    private static void AddConnectionDeclaredHeaders(HashSet<string> target, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        foreach (var token in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            target.Add(token);
        }
    }

    private static void LogDroppedHeader(ILogger logger, string direction, string headerName, string reason)
    {
        logger.LogDebug(
            "Dropped downstream proxy {Direction} header {HeaderName}. Reason={Reason}",
            direction,
            headerName,
            reason);
    }
}
