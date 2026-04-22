using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Maps the reusable authentication endpoints used by the OIDC host infrastructure.
/// </summary>
public static class AuthenticationEndpoints
{
    /// <summary>
    /// The name of the domain hint parameter used in authentication requests.
    /// </summary>
    public const string DomainHintParameterName = "domain_hint";

    /// <summary>
    /// Maps the reusable login, logout, and session endpoints.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder used to register the endpoints.</param>
    /// <param name="authOptions">The host authentication options that define the endpoint base path and session validation behavior.</param>
    public static void MapLoginLogoutAndSessionEndpoints(IEndpointRouteBuilder endpoints, OidcAuthenticationOptions authOptions)
    {
        var group = endpoints.MapGroup(authOptions.EndpointBasePath);

        group.MapGet("/login", (string? returnUrl, string? domain_hint) =>
        {
            var safeReturnUrl = SanitizeReturnUrl(returnUrl);
            var logger = endpoints.ServiceProvider.GetRequiredService<ILoggerFactory>()
                .CreateLogger(typeof(AuthenticationEndpoints).FullName!);
            OidcEndpointLog.LoginRequested(logger, $"{authOptions.EndpointBasePath}/login");
            var properties = new AuthenticationProperties
            {
                RedirectUri = safeReturnUrl
            };

            if (!string.IsNullOrWhiteSpace(domain_hint))
            {
                properties.Items[DomainHintParameterName] = domain_hint;
            }

            return Results.Challenge(
                properties,
                [OpenIdConnectDefaults.AuthenticationScheme]);
        })
        .AllowAnonymous();

        group.MapPost("/logout", LogoutAsync)
            .WithMetadata(new RequireAntiforgeryTokenAttribute());

        group.MapGet("/session", async (
            HttpContext httpContext,
            IDownstreamUserTokenProvider tokenProvider,
            IDownstreamUserTokenStore tokenStore,
            OidcSessionCleanupService sessionCleanupService,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken) =>
        {
            if (!await TryEnsureAuthenticatedSessionAsync(httpContext, authOptions, tokenProvider, tokenStore, sessionCleanupService, cancellationToken, loggerFactory, $"{authOptions.EndpointBasePath}/session"))
            {
                return;
            }

            httpContext.Response.StatusCode = StatusCodes.Status204NoContent;
        })
        .DisableAntiforgery()
        .AllowAnonymous();

        group.MapGet("/principal", async (
            HttpContext httpContext,
            IDownstreamUserTokenProvider tokenProvider,
            IDownstreamUserTokenStore tokenStore,
            OidcSessionCleanupService sessionCleanupService,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken) =>
        {
            if (!await TryEnsureAuthenticatedSessionAsync(httpContext, authOptions, tokenProvider, tokenStore, sessionCleanupService, cancellationToken, loggerFactory, $"{authOptions.EndpointBasePath}/principal"))
            {
                return;
            }

            await httpContext.Response.WriteAsJsonAsync(AuthenticationPrincipalSnapshot.FromPrincipal(httpContext.User), cancellationToken);
        })
        .DisableAntiforgery()
        .AllowAnonymous();
    }

    /// <summary>
    /// Sanitizes a return URL so that only safe application-relative URLs are preserved.
    /// </summary>
    /// <param name="returnUrl">The return URL supplied by the client.</param>
    /// <returns>A safe application-relative return URL.</returns>
    internal static string SanitizeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return "/";
        }

        if (Uri.TryCreate(returnUrl, UriKind.Relative, out var relativeUri) &&
            returnUrl.StartsWith("/", StringComparison.Ordinal) &&
            !returnUrl.StartsWith("//", StringComparison.Ordinal))
        {
            return relativeUri.ToString();
        }

        return "/";
    }

    internal static async Task<IResult> LogoutAsync(
        HttpContext httpContext,
        IAntiforgery antiforgery,
        IDownstreamUserTokenStore tokenStore,
        string? returnUrl,
        ILoggerFactory loggerFactory)
    {
        var logger = loggerFactory.CreateLogger(typeof(AuthenticationEndpoints).FullName!);
        using var scope = logger.BeginScope(OidcLogScopes.Create(httpContext.TraceIdentifier, endpoint: "/logout", flowStep: "logout"));
        OidcEndpointLog.LogoutRequested(logger, "/logout", httpContext.User.Identity?.IsAuthenticated is true);

        var antiforgeryValidationFeature = httpContext.Features.Get<IAntiforgeryValidationFeature>();
        if (antiforgeryValidationFeature is { IsValid: false })
        {
            OidcEndpointLog.AntiforgeryValidationFailed(logger, "/logout", "feature");
            return TypedResults.BadRequest();
        }

        if (!await antiforgery.IsRequestValidAsync(httpContext))
        {
            OidcEndpointLog.AntiforgeryValidationFailed(logger, "/logout", "service");
            return TypedResults.BadRequest();
        }

        if (httpContext.User.Identity?.IsAuthenticated is true)
        {
            await tokenStore.RemoveAsync(httpContext.User, httpContext.RequestAborted);
        }

        var safeReturnUrl = SanitizeReturnUrl(returnUrl);
        OidcEndpointLog.LogoutCompleted(logger, "/logout", "signout-issued");
        return TypedResults.SignOut(
            new AuthenticationProperties
            {
                RedirectUri = safeReturnUrl
            },
            [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]);
    }

    internal static async Task<bool> TryEnsureAuthenticatedSessionAsync(
        HttpContext httpContext,
        OidcAuthenticationOptions authOptions,
        IDownstreamUserTokenProvider tokenProvider,
        IDownstreamUserTokenStore tokenStore,
        OidcSessionCleanupService sessionCleanupService,
        CancellationToken cancellationToken,
        ILoggerFactory loggerFactory,
        string endpoint)
    {
        var logger = loggerFactory.CreateLogger(typeof(AuthenticationEndpoints).FullName!);
        using var scope = logger.BeginScope(OidcLogScopes.Create(httpContext.TraceIdentifier, endpoint: endpoint, flowStep: "session-validation"));
        OidcEndpointLog.SessionValidationStarted(
            logger,
            endpoint,
            httpContext.User.Identity?.IsAuthenticated is true,
            !string.IsNullOrWhiteSpace(authOptions.SessionValidationDownstreamApiName));

        if (httpContext.User.Identity?.IsAuthenticated is not true)
        {
            OidcEndpointLog.SessionValidationFailed(logger, endpoint, "anonymous-user");
            await sessionCleanupService.WriteUnauthorizedAsync(httpContext, "anonymous-user");
            return false;
        }

        var timeProvider = httpContext.RequestServices.GetRequiredService<TimeProvider>();
        if (OidcSessionTimeoutMetadata.HasAbsoluteSessionExpired(httpContext.User, timeProvider, out var absoluteExpiresAtUtc))
        {
            OidcSessionCleanupLog.SessionAbsoluteTimeoutExpired(logger, httpContext.Request.Path.Value ?? endpoint, absoluteExpiresAtUtc);
            OidcEndpointLog.SessionValidationFailed(logger, endpoint, "absolute-timeout-expired");
            await sessionCleanupService.WriteUnauthorizedAsync(httpContext, "absolute-timeout-expired", httpContext.User);
            return false;
        }

        var downstreamApiName = authOptions.SessionValidationDownstreamApiName;

        if (string.IsNullOrWhiteSpace(downstreamApiName))
        {
            if (await tokenStore.GetSessionTokenSetAsync(httpContext.User, cancellationToken) is null)
            {
                OidcEndpointLog.SessionValidationFailed(logger, endpoint, "missing-session-token");
                await sessionCleanupService.WriteUnauthorizedAsync(httpContext, "missing-session-token");
                return false;
            }

            OidcEndpointLog.SessionValidationSucceeded(logger, endpoint, "session-token-present");
            return true;
        }

        try
        {
            _ = await tokenProvider.GetAccessTokenAsync(httpContext.User, downstreamApiName, cancellationToken);
            OidcEndpointLog.SessionValidationSucceeded(logger, endpoint, "downstream-token-available");
            return true;
        }
        catch (OidcReauthenticationRequiredException)
        {
            OidcEndpointLog.SessionValidationFailed(logger, endpoint, "reauthentication-required");
            await sessionCleanupService.WriteUnauthorizedAsync(httpContext, "reauthentication-required");
            return false;
        }
        catch (OidcTokenRefreshFailedException)
        {
            OidcEndpointLog.SessionValidationUnavailable(logger, endpoint, "token-refresh-failed");
            httpContext.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return false;
        }
    }
}
