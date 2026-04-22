using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Converts authentication challenges and authorization failures to status codes for API and proxy requests.
/// </summary>
internal sealed class ApiAwareAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    private static readonly AuthorizationMiddlewareResultHandler DefaultHandler = new();
    private readonly IAuthorizationMiddlewareResultHandler fallbackHandler;
    private readonly ProxyEndpointMatcher proxyEndpointMatcher;
    private readonly ILogger<ApiAwareAuthorizationMiddlewareResultHandler> logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiAwareAuthorizationMiddlewareResultHandler"/> class.
    /// </summary>
    /// <param name="proxyEndpointMatcher">The proxy endpoint matcher used to detect proxy requests.</param>
    public ApiAwareAuthorizationMiddlewareResultHandler(
        ProxyEndpointMatcher proxyEndpointMatcher,
        ILogger<ApiAwareAuthorizationMiddlewareResultHandler> logger)
        : this(DefaultHandler, proxyEndpointMatcher, logger)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiAwareAuthorizationMiddlewareResultHandler"/> class.
    /// </summary>
    /// <param name="fallbackHandler">The fallback handler used when redirect suppression is not required.</param>
    /// <param name="proxyEndpointMatcher">The proxy endpoint matcher used to detect proxy requests.</param>
    internal ApiAwareAuthorizationMiddlewareResultHandler(
        IAuthorizationMiddlewareResultHandler fallbackHandler,
        ProxyEndpointMatcher proxyEndpointMatcher,
        ILogger<ApiAwareAuthorizationMiddlewareResultHandler> logger)
    {
        this.fallbackHandler = fallbackHandler;
        this.proxyEndpointMatcher = proxyEndpointMatcher;
        this.logger = logger;
    }

    /// <summary>
    /// Handles the authorization result for the current request.
    /// </summary>
    /// <param name="next">The next middleware in the request pipeline.</param>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="policy">The authorization policy that was evaluated.</param>
    /// <param name="authorizeResult">The result of the authorization evaluation.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        var (shouldSuppressRedirect, reason) = EvaluateRedirectSuppression(context, proxyEndpointMatcher);
        OidcAuthorizationLog.AuthorizationRedirectSuppressed(logger, shouldSuppressRedirect, reason);

        if (!shouldSuppressRedirect)
        {
            return fallbackHandler.HandleAsync(next, context, policy, authorizeResult);
        }

        if (authorizeResult.Challenged)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            OidcAuthorizationLog.AuthorizationStatusCodeWritten(logger, StatusCodes.Status401Unauthorized, reason);
            return Task.CompletedTask;
        }

        if (authorizeResult.Forbidden)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            OidcAuthorizationLog.AuthorizationStatusCodeWritten(logger, StatusCodes.Status403Forbidden, reason);
            return Task.CompletedTask;
        }

        return fallbackHandler.HandleAsync(next, context, policy, authorizeResult);
    }

    /// <summary>
    /// Determines whether authentication redirects should be suppressed for the current request.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="proxyEndpointMatcher">An optional matcher used to detect proxy requests before endpoint selection completes.</param>
    /// <returns><see langword="true"/> when authentication redirects should be suppressed; otherwise, <see langword="false"/>.</returns>
    internal static bool ShouldSuppressRedirect(HttpContext context, ProxyEndpointMatcher? proxyEndpointMatcher = null)
        => EvaluateRedirectSuppression(context, proxyEndpointMatcher).ShouldSuppressRedirect;

    private static (bool ShouldSuppressRedirect, string Reason) EvaluateRedirectSuppression(HttpContext context, ProxyEndpointMatcher? proxyEndpointMatcher = null)
    {
        if (HasSuppressRedirectMetadata(context))
        {
            return (true, "suppress-auth-redirect-metadata");
        }

        if (HasProxyEndpointMetadata(context))
        {
            return (true, "proxy-endpoint-metadata");
        }

        if (proxyEndpointMatcher?.IsProxyRequest(context.Request) == true)
        {
            return (true, "proxy-route-match");
        }

        return IsApiRequest(context.Request)
            ? (true, "api-request")
            : (false, "fallback-handler");
    }

    /// <summary>
    /// Determines whether the selected endpoint explicitly suppresses authentication redirects.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <returns><see langword="true"/> when the endpoint contains redirect suppression metadata; otherwise, <see langword="false"/>.</returns>
    internal static bool HasSuppressRedirectMetadata(HttpContext context) =>
        context.GetEndpoint()?.Metadata.GetMetadata<SuppressAuthRedirectMetadata>() is not null;

    /// <summary>
    /// Determines whether the selected endpoint is marked as a proxy endpoint.
    /// </summary>
    /// <param name="context">The current HTTP context.</param>
    /// <returns><see langword="true"/> when the endpoint is marked as a proxy endpoint; otherwise, <see langword="false"/>.</returns>
    internal static bool HasProxyEndpointMetadata(HttpContext context) =>
        context.GetEndpoint()?.Metadata.GetMetadata<ProxyEndpointMetadata>() is not null;

    /// <summary>
    /// Determines whether the request should be treated as an API request.
    /// </summary>
    /// <param name="request">The HTTP request to evaluate.</param>
    /// <returns><see langword="true"/> when the request targets an API-style endpoint; otherwise, <see langword="false"/>.</returns>
    internal static bool IsApiRequest(HttpRequest request)
    {
        if (request.Path.StartsWithSegments(OidcAuthenticationConstants.RequestPaths.ApiPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return AcceptsJson(request.Headers.Accept);
    }

    private static bool AcceptsJson(string? acceptHeader)
    {
        if (string.IsNullOrWhiteSpace(acceptHeader))
        {
            return false;
        }

        return acceptHeader.Contains(OidcAuthenticationConstants.MediaTypes.Json, StringComparison.OrdinalIgnoreCase) ||
               acceptHeader.Contains(OidcAuthenticationConstants.MediaTypes.JsonStructuredSyntaxSuffix, StringComparison.OrdinalIgnoreCase);
    }
}
