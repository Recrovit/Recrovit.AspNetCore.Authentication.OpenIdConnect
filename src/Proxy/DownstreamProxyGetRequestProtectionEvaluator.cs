using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

internal interface IDownstreamProxyGetRequestProtectionEvaluator
{
    bool IsRequestAllowed(HttpContext context, out string reason);
}

internal sealed class DownstreamProxyGetRequestProtectionEvaluator(
    IOptions<OidcAuthenticationOptions> options,
    ILogger<DownstreamProxyGetRequestProtectionEvaluator> logger) : IDownstreamProxyGetRequestProtectionEvaluator
{
    private const string FetchMetadataHeaderName = "Sec-Fetch-Site";
    private const string OriginHeaderName = "Origin";

    public bool IsRequestAllowed(HttpContext context, out string reason)
    {
        var protectionOptions = options.Value.DownstreamProxyGetProtection;

        if (!protectionOptions.Enabled)
        {
            reason = "disabled";
            return true;
        }

        if (!HttpMethods.IsGet(context.Request.Method))
        {
            reason = "non-get";
            return true;
        }

        if (context.WebSockets.IsWebSocketRequest)
        {
            reason = "websocket";
            return true;
        }

        if (context.GetEndpoint()?.Metadata.GetMetadata<ProxyEndpointMetadata>() is null)
        {
            reason = "non-proxy-endpoint";
            return true;
        }

        if (protectionOptions.Mode != ProxyGetRequestProtectionMode.FetchMetadataFirst)
        {
            reason = "unsupported-mode";
            return false;
        }

        if (context.Request.Headers.TryGetValue(FetchMetadataHeaderName, out var fetchMetadataHeaderValues))
        {
            var fetchMetadataSite = fetchMetadataHeaderValues.ToString().Trim();
            if (IsAllowedFetchMetadataSite(fetchMetadataSite))
            {
                reason = $"fetch-metadata:{fetchMetadataSite}";
                return true;
            }

            reason = $"fetch-metadata:{(string.IsNullOrWhiteSpace(fetchMetadataSite) ? "invalid" : fetchMetadataSite)}";
            LogBlockedRequest(context, reason);
            return false;
        }

        if (protectionOptions.AllowOriginFallback
            && context.Request.Headers.TryGetValue(OriginHeaderName, out var originHeaderValues)
            && IsAllowedOrigin(context, originHeaderValues.ToString(), protectionOptions))
        {
            reason = "origin";
            return true;
        }

        if (HasValidCustomHeader(context, protectionOptions))
        {
            reason = "custom-header";
            return true;
        }

        reason = "missing-browser-signal";
        LogBlockedRequest(context, reason);
        return false;
    }

    private static bool IsAllowedFetchMetadataSite(string fetchMetadataSite)
        => fetchMetadataSite.Equals("same-origin", StringComparison.OrdinalIgnoreCase)
            || fetchMetadataSite.Equals("same-site", StringComparison.OrdinalIgnoreCase)
            || fetchMetadataSite.Equals("none", StringComparison.OrdinalIgnoreCase);

    private static bool IsAllowedOrigin(HttpContext context, string originHeaderValue, DownstreamProxyGetProtectionOptions protectionOptions)
    {
        if (!TryNormalizeOrigin(originHeaderValue, out var requestOrigin))
        {
            return false;
        }

        if (TryNormalizeOrigin($"{context.Request.Scheme}://{context.Request.Host.Value}", out var currentOrigin)
            && string.Equals(requestOrigin, currentOrigin, StringComparison.Ordinal))
        {
            return true;
        }

        return protectionOptions.AllowedOrigins
            .Where(static origin => !string.IsNullOrWhiteSpace(origin))
            .Select(static origin => NormalizeOrigin(origin))
            .Any(allowedOrigin => string.Equals(requestOrigin, allowedOrigin, StringComparison.Ordinal));
    }

    private static bool HasValidCustomHeader(HttpContext context, DownstreamProxyGetProtectionOptions protectionOptions)
    {
        if (string.IsNullOrWhiteSpace(protectionOptions.CustomHeaderName)
            || string.IsNullOrWhiteSpace(protectionOptions.CustomHeaderValue))
        {
            return false;
        }

        return context.Request.Headers.TryGetValue(protectionOptions.CustomHeaderName, out var headerValues)
            && headerValues.Any(value => string.Equals(value, protectionOptions.CustomHeaderValue, StringComparison.Ordinal));
    }

    private static bool TryNormalizeOrigin(string origin, out string normalizedOrigin)
    {
        normalizedOrigin = string.Empty;
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(uri.PathAndQuery) && uri.PathAndQuery != "/")
        {
            return false;
        }

        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            return false;
        }

        normalizedOrigin = NormalizeOrigin(uri);
        return true;
    }

    private static string NormalizeOrigin(string origin)
    {
        if (!TryNormalizeOrigin(origin, out var normalizedOrigin))
        {
            return string.Empty;
        }

        return normalizedOrigin;
    }

    private static string NormalizeOrigin(Uri uri)
    {
        var builder = new UriBuilder(uri.Scheme.ToLowerInvariant(), uri.Host.ToLowerInvariant(), uri.IsDefaultPort ? -1 : uri.Port);
        return builder.Uri.GetLeftPart(UriPartial.Authority);
    }

    private void LogBlockedRequest(HttpContext context, string reason)
    {
        OidcProxyLog.DownstreamProxyGetRequestRejected(
            logger,
            context.Request.Path.Value ?? "/",
            reason);
    }
}
