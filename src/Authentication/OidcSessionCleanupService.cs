using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Clears the local authentication session and writes reauthentication responses.
/// </summary>
internal sealed class OidcSessionCleanupService(IDownstreamUserTokenStore tokenStore, ILogger<OidcSessionCleanupService> logger)
{
    /// <summary>
    /// Clears the local cookie-based session and removes any stored user tokens.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public async Task ClearSessionAsync(HttpContext httpContext, string reason = "unspecified", ClaimsPrincipal? sessionPrincipal = null)
    {
        using var scope = logger.BeginScope(OidcLogScopes.Create(httpContext.TraceIdentifier, flowStep: "session-cleanup"));
        var principalToCleanup = sessionPrincipal ?? httpContext.User;
        var isAuthenticated = principalToCleanup.Identity?.IsAuthenticated is true;
        OidcSessionCleanupLog.SessionCleanupStarted(logger, reason, isAuthenticated);

        if (isAuthenticated)
        {
            await tokenStore.RemoveAsync(principalToCleanup, httpContext.RequestAborted);
            OidcSessionCleanupLog.SessionCleanupTokensRemoved(logger, reason);
        }

        await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        OidcSessionCleanupLog.SessionCleanupCookieCleared(logger, reason);
    }

    /// <summary>
    /// Clears the local session and writes an unauthorized response that signals reauthentication.
    /// </summary>
    /// <param name="httpContext">The current HTTP context.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    public async Task WriteUnauthorizedAsync(HttpContext httpContext, string reason = "reauth-required", ClaimsPrincipal? sessionPrincipal = null)
    {
        await ClearSessionAsync(httpContext, reason, sessionPrincipal);
        httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
        httpContext.Response.Headers[OidcAuthenticationConstants.ResponseHeaders.ReauthenticationRequired]
            = OidcAuthenticationConstants.ResponseHeaders.ReauthenticationRequiredValue;
        OidcSessionCleanupLog.SessionCleanupUnauthorizedWritten(logger, reason, StatusCodes.Status401Unauthorized);
    }
}
