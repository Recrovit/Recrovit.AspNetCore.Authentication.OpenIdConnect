using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

internal interface IDownstreamProxyRequestProtectionEvaluator
{
    DownstreamProxyRequestProtectionEvaluation Evaluate(HttpContext context);
}

internal readonly record struct DownstreamProxyRequestProtectionEvaluation(
    bool IsAllowed,
    bool RequiresAntiforgeryValidation,
    int FailureStatusCode,
    string RequestType,
    string Reason);

internal sealed class DownstreamProxyRequestProtectionEvaluator(
    IOptions<OidcAuthenticationOptions> options,
    ILogger<DownstreamProxyRequestProtectionEvaluator> logger) : IDownstreamProxyRequestProtectionEvaluator
{
    private const string FetchMetadataHeaderName = "Sec-Fetch-Site";
    private const string OriginHeaderName = "Origin";

    public DownstreamProxyRequestProtectionEvaluation Evaluate(HttpContext context)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<ProxyEndpointMetadata>() is null)
        {
            return Allow("non-proxy-endpoint");
        }

        var protectionOptions = options.Value.DownstreamProxyRequestProtection;
        if (protectionOptions.Mode != ProxyRequestProtectionMode.FetchMetadataFirst)
        {
            return Reject(context, StatusCodes.Status403Forbidden, GetRequestType(context), "unsupported-mode");
        }

        if (context.WebSockets.IsWebSocketRequest)
        {
            return EvaluateWebSocketRequest(context, protectionOptions);
        }

        return EvaluateHttpRequest(context, protectionOptions);
    }

    private DownstreamProxyRequestProtectionEvaluation EvaluateHttpRequest(
        HttpContext context,
        DownstreamProxyRequestProtectionOptions protectionOptions)
    {
        var request = context.Request;
        var method = request.Method;
        var requiresAntiforgeryValidation = !IsSafeMethod(method);

        if (TryGetSingleHeaderValue(request.Headers, FetchMetadataHeaderName, out var fetchMetadataSite, out var fetchHeaderReason))
        {
            if (!TryNormalizeFetchMetadataSite(fetchMetadataSite!, protectionOptions.AllowSameSite, out var normalizedFetchMetadataSite))
            {
                return Reject(context, StatusCodes.Status403Forbidden, "http", $"fetch-metadata:{fetchHeaderReason ?? NormalizeReasonValue(fetchMetadataSite)}");
            }

            if (TryGetSingleHeaderValue(request.Headers, OriginHeaderName, out var originHeaderValue, out var originHeaderReason))
            {
                if (!IsAllowedOriginForFetchMetadata(context, originHeaderValue!, normalizedFetchMetadataSite!, protectionOptions))
                {
                    return Reject(context, StatusCodes.Status403Forbidden, "http", $"origin:{originHeaderReason ?? "mismatch"}");
                }
            }
            else if (originHeaderReason is not null)
            {
                return Reject(context, StatusCodes.Status403Forbidden, "http", $"origin:{originHeaderReason}");
            }

            return Allow($"fetch-metadata:{normalizedFetchMetadataSite}", requiresAntiforgeryValidation, "http");
        }

        if (fetchHeaderReason is not null)
        {
            return Reject(context, StatusCodes.Status403Forbidden, "http", $"fetch-metadata:{fetchHeaderReason}");
        }

        if (TryGetSingleHeaderValue(request.Headers, OriginHeaderName, out var originFallback, out var originReason))
        {
            if (IsAllowedHttpOrigin(context, originFallback!, protectionOptions))
            {
                return Allow("origin", requiresAntiforgeryValidation, "http");
            }

            return Reject(context, StatusCodes.Status403Forbidden, "http", "origin:mismatch");
        }

        if (originReason is not null)
        {
            return Reject(context, StatusCodes.Status403Forbidden, "http", $"origin:{originReason}");
        }

        if (HasValidCustomHeader(context, protectionOptions))
        {
            return Allow("custom-header", requiresAntiforgeryValidation, "http");
        }

        return Reject(context, StatusCodes.Status403Forbidden, "http", "missing-browser-signal");
    }

    private DownstreamProxyRequestProtectionEvaluation EvaluateWebSocketRequest(
        HttpContext context,
        DownstreamProxyRequestProtectionOptions protectionOptions)
    {
        if (TryGetSingleHeaderValue(context.Request.Headers, OriginHeaderName, out var originHeaderValue, out var originReason))
        {
            if (string.Equals(originHeaderValue, "null", StringComparison.OrdinalIgnoreCase))
            {
                return Reject(context, StatusCodes.Status403Forbidden, "websocket", "origin:null");
            }

            if (IsAllowedWebSocketOrigin(context, originHeaderValue!, protectionOptions))
            {
                return Allow("origin", requestType: "websocket");
            }

            return Reject(context, StatusCodes.Status403Forbidden, "websocket", $"origin:{originReason ?? "mismatch"}");
        }

        if (originReason is not null)
        {
            return Reject(context, StatusCodes.Status403Forbidden, "websocket", $"origin:{originReason}");
        }

        if (protectionOptions.AllowMissingWebSocketOrigin)
        {
            return Allow("origin-missing:allowed", requestType: "websocket");
        }

        return Reject(context, StatusCodes.Status403Forbidden, "websocket", "origin:missing");
    }

    private static bool IsSafeMethod(string method)
        => HttpMethods.IsGet(method)
            || HttpMethods.IsHead(method)
            || HttpMethods.IsOptions(method)
            || HttpMethods.IsTrace(method);

    private static bool HasValidCustomHeader(HttpContext context, DownstreamProxyRequestProtectionOptions protectionOptions)
    {
        if (string.IsNullOrWhiteSpace(protectionOptions.CustomHeaderName)
            || string.IsNullOrWhiteSpace(protectionOptions.CustomHeaderValue))
        {
            return false;
        }

        return context.Request.Headers.TryGetValue(protectionOptions.CustomHeaderName, out var headerValues)
            && headerValues.Count == 1
            && string.Equals(headerValues[0], protectionOptions.CustomHeaderValue, StringComparison.Ordinal);
    }

    private static bool IsAllowedOriginForFetchMetadata(
        HttpContext context,
        string originHeaderValue,
        string normalizedFetchMetadataSite,
        DownstreamProxyRequestProtectionOptions protectionOptions)
    {
        if (!DownstreamProxyOriginHelper.TryNormalizeOrigin(originHeaderValue, out var requestOrigin)
            || !DownstreamProxyOriginHelper.TryGetCurrentOrigin(context.Request, out var currentOrigin))
        {
            return false;
        }

        if (normalizedFetchMetadataSite.Equals("same-origin", StringComparison.Ordinal))
        {
            return string.Equals(requestOrigin, currentOrigin, StringComparison.Ordinal);
        }

        return string.Equals(requestOrigin, currentOrigin, StringComparison.Ordinal)
            || protectionOptions.AllowedHttpOrigins.Any(origin =>
                string.Equals(DownstreamProxyOriginHelper.NormalizeOrigin(origin), requestOrigin, StringComparison.Ordinal));
    }

    private static bool IsAllowedHttpOrigin(
        HttpContext context,
        string originHeaderValue,
        DownstreamProxyRequestProtectionOptions protectionOptions)
    {
        if (!DownstreamProxyOriginHelper.TryNormalizeOrigin(originHeaderValue, out var requestOrigin))
        {
            return false;
        }

        return DownstreamProxyOriginHelper.TryGetCurrentOrigin(context.Request, out var currentOrigin)
            && string.Equals(requestOrigin, currentOrigin, StringComparison.Ordinal)
            || protectionOptions.AllowedHttpOrigins.Any(origin =>
                string.Equals(DownstreamProxyOriginHelper.NormalizeOrigin(origin), requestOrigin, StringComparison.Ordinal));
    }

    private static bool IsAllowedWebSocketOrigin(
        HttpContext context,
        string originHeaderValue,
        DownstreamProxyRequestProtectionOptions protectionOptions)
    {
        if (!DownstreamProxyOriginHelper.TryNormalizeOrigin(originHeaderValue, out var requestOrigin))
        {
            return false;
        }

        return DownstreamProxyOriginHelper.TryGetCurrentOrigin(context.Request, out var currentOrigin)
            && string.Equals(requestOrigin, currentOrigin, StringComparison.Ordinal)
            || protectionOptions.AllowedWebSocketOrigins.Any(origin =>
                string.Equals(DownstreamProxyOriginHelper.NormalizeOrigin(origin), requestOrigin, StringComparison.Ordinal));
    }

    private static bool TryGetSingleHeaderValue(
        IHeaderDictionary headers,
        string headerName,
        out string? value,
        out string? reason)
    {
        value = null;
        reason = null;

        if (!headers.TryGetValue(headerName, out var headerValues))
        {
            return false;
        }

        if (!TryGetSingleHeaderValue(headerValues, out value))
        {
            reason = "multiple";
            return false;
        }

        value = value!.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            value = null;
            reason = "invalid";
            return false;
        }

        return true;
    }

    private static bool TryGetSingleHeaderValue(StringValues headerValues, out string? value)
    {
        value = null;
        if (headerValues.Count != 1)
        {
            return false;
        }

        var rawValue = headerValues[0];
        if (string.IsNullOrWhiteSpace(rawValue)
            || rawValue.Contains(',', StringComparison.Ordinal))
        {
            return false;
        }

        value = rawValue;
        return true;
    }

    private static bool TryNormalizeFetchMetadataSite(
        string fetchMetadataSite,
        bool allowSameSite,
        out string? normalizedFetchMetadataSite)
    {
        normalizedFetchMetadataSite = fetchMetadataSite.Trim().ToLowerInvariant();
        return normalizedFetchMetadataSite switch
        {
            "same-origin" => true,
            "same-site" => allowSameSite,
            _ => false
        };
    }

    private static string NormalizeReasonValue(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? "invalid"
            : value.Trim().ToLowerInvariant();

    private static string GetRequestType(HttpContext context)
        => context.WebSockets.IsWebSocketRequest ? "websocket" : "http";

    private DownstreamProxyRequestProtectionEvaluation Reject(HttpContext context, int statusCode, string requestType, string reason)
    {
        OidcProxyLog.DownstreamProxyRequestRejected(
            logger,
            context.Request.Path.Value ?? "/",
            context.Request.Method,
            requestType,
            reason);
        return new DownstreamProxyRequestProtectionEvaluation(false, false, statusCode, requestType, reason);
    }

    private static DownstreamProxyRequestProtectionEvaluation Allow(
        string reason,
        bool requiresAntiforgeryValidation = false,
        string requestType = "http")
        => new(true, requiresAntiforgeryValidation, StatusCodes.Status200OK, requestType, reason);
}

internal static class DownstreamProxyOriginHelper
{
    public static bool IsValidConfiguredOrigin(string? origin)
        => TryNormalizeOrigin(origin, out _);

    public static bool TryGetCurrentOrigin(HttpRequest request, out string normalizedOrigin)
        => TryNormalizeOrigin($"{request.Scheme}://{request.Host.Value}", out normalizedOrigin);

    public static bool TryNormalizeOrigin(string? origin, out string normalizedOrigin)
    {
        normalizedOrigin = string.Empty;
        if (string.IsNullOrWhiteSpace(origin)
            || !Uri.TryCreate(origin, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(uri.UserInfo)
            || !string.Equals(uri.AbsolutePath, "/", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        normalizedOrigin = NormalizeOrigin(uri);
        return true;
    }

    public static string NormalizeOrigin(string origin)
        => TryNormalizeOrigin(origin, out var normalizedOrigin)
            ? normalizedOrigin
            : string.Empty;

    private static string NormalizeOrigin(Uri uri)
    {
        var builder = new UriBuilder(
            uri.Scheme.ToLowerInvariant(),
            uri.Host.ToLowerInvariant(),
            uri.IsDefaultPort ? -1 : uri.Port);
        return builder.Uri.GetLeftPart(UriPartial.Authority);
    }
}
