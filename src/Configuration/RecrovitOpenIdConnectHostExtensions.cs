using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Provides host setup extensions for the Recrovit OpenID Connect package.
/// </summary>
public static class RecrovitOpenIdConnectHostExtensions
{
    /// <summary>
    /// Registers the reusable Recrovit OpenID Connect application infrastructure.
    /// </summary>
    /// <param name="builder">The web application builder to configure.</param>
    /// <returns>The same web application builder instance.</returns>
    public static WebApplicationBuilder AddRecrovitOpenIdConnectInfrastructure(this WebApplicationBuilder builder)
    {
        builder.Services.AddCascadingAuthenticationState();
        builder.Services.AddAntiforgery();
        builder.Services.AddOidcAuthenticationInfrastructure(builder.Configuration, builder.Environment);

        return builder;
    }

    /// <summary>
    /// Enables forwarded headers processing for the Recrovit OpenID Connect host when configured.
    /// </summary>
    /// <param name="app">The application builder to configure.</param>
    /// <returns>The same application builder instance.</returns>
    public static IApplicationBuilder UseRecrovitOpenIdConnectForwardedHeaders(this WebApplication app)
    {
        var hostSecurityOptions = app.Services.GetRequiredService<IOptions<HostSecurityOptions>>().Value;
        var logger = app.Services.GetRequiredService<ILoggerFactory>()
            .CreateLogger("Recrovit.AspNetCore.Authentication.OpenIdConnect.ForwardedHeaders");
        OidcInfrastructureLog.ForwardedHeadersModeEvaluated(logger, hostSecurityOptions.ForwardedHeadersEnabled);
        if (hostSecurityOptions.ForwardedHeadersEnabled)
        {
            app.UseForwardedHeaders(ForwardedHeadersConfiguration.CreateOptions(hostSecurityOptions));
        }

        return app;
    }

    /// <summary>
    /// Enables status code pages re-execution for non-proxy requests in the Recrovit OpenID Connect host.
    /// </summary>
    /// <param name="app">The application builder to configure.</param>
    /// <param name="pathFormat">The path format used when re-executing the request.</param>
    /// <param name="queryFormat">The optional query string format used when re-executing the request.</param>
    /// <param name="createScopeForStatusCodePages"><see langword="true"/> to create a new service scope for the re-executed pipeline; otherwise, <see langword="false"/>.</param>
    /// <returns>The same web application instance.</returns>
    public static WebApplication UseRecrovitOpenIdConnectStatusCodePagesWithReExecute(
        this WebApplication app,
        string pathFormat,
        string? queryFormat = null,
        bool createScopeForStatusCodePages = false)
    {
        app.UseWhen(
            context => !context.RequestServices.GetRequiredService<ProxyEndpointMatcher>().IsProxyRequest(context.Request),
            branch => branch.UseStatusCodePagesWithReExecute(pathFormat, queryFormat: queryFormat, createScopeForStatusCodePages: createScopeForStatusCodePages));

        return app;
    }

    /// <summary>
    /// Adds the authentication, authorization, and antiforgery middleware required by the Recrovit OpenID Connect package.
    /// </summary>
    /// <param name="app">The application to configure.</param>
    /// <returns>The same web application instance.</returns>
    public static WebApplication UseRecrovitOpenIdConnectAuthentication(this WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            var openIdConnectOptions = context.RequestServices
                .GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
                .Get(OpenIdConnectDefaults.AuthenticationScheme);
            var hostOptions = context.RequestServices
                .GetRequiredService<IOptions<OidcAuthenticationOptions>>()
                .Value;
            var classification = await OidcRemoteFailureClassifier.ClassifyAsync(
                context.Request,
                openIdConnectOptions.CallbackPath,
                context.RequestAborted);

            if (!classification.IsHandledRemoteFailure || !classification.ShouldRedirect)
            {
                await next();
                return;
            }

            var providerName = context.RequestServices
                .GetRequiredService<IOptions<ActiveOidcProviderOptions>>()
                .Value
                .ProviderName;
            var logger = context.RequestServices
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger("Recrovit.AspNetCore.Authentication.OpenIdConnect.RemoteFailure");
            using var scope = logger.BeginScope(OidcLogScopes.Create(
                context.TraceIdentifier,
                providerName: providerName,
                endpoint: openIdConnectOptions.CallbackPath,
                flowStep: "remote-failure-middleware"));

            if (classification.ShouldCleanupCorrelationCookies)
            {
                OidcRemoteFailureClassifier.DeleteTransientCookies(context, openIdConnectOptions);
            }

            OidcInfrastructureLog.RemoteFailureIntercepted(
                logger,
                providerName,
                classification.Kind.ToString(),
                classification.Error ?? "(none)",
                classification.ShouldRedirect,
                classification.ShouldCleanupCorrelationCookies);

            context.Response.Redirect(OidcRemoteFailureClassifier.GetSafeRedirectPath(hostOptions.RemoteFailureRedirectPath));
            OidcInfrastructureLog.RemoteFailureRedirected(
                logger,
                providerName,
                classification.Kind.ToString(),
                classification.ShouldCleanupCorrelationCookies);
        });
        app.UseAuthentication();
        app.Use(async (context, next) =>
        {
            if (OidcSessionTimeoutMetadata.TryGetExpiredSession(context, out var expiredSession))
            {
                var sessionCleanupService = context.RequestServices.GetRequiredService<OidcSessionCleanupService>();
                await sessionCleanupService.WriteUnauthorizedAsync(context, expiredSession.Reason, expiredSession.SessionPrincipal);
                return;
            }

            await next();
        });
        app.Use(async (context, next) =>
        {
            try
            {
                await next();
            }
            catch (OidcReauthenticationRequiredException)
            {
                if (context.Response.HasStarted)
                {
                    throw;
                }

                var sessionCleanupService = context.RequestServices.GetRequiredService<OidcSessionCleanupService>();
                await sessionCleanupService.WriteUnauthorizedAsync(context);
            }
        });
        app.UseAuthorization();
        app.UseAntiforgery();
        return app;
    }

    /// <summary>
    /// Enables WebSocket support required by downstream proxy transport endpoints.
    /// </summary>
    /// <param name="app">The application to configure.</param>
    /// <returns>The same web application instance.</returns>
    public static WebApplication UseRecrovitOpenIdConnectProxyTransports(this WebApplication app)
    {
        app.UseWebSockets();
        return app;
    }

    /// <summary>
    /// Maps the reusable Recrovit OpenID Connect endpoints.
    /// </summary>
    /// <param name="app">The application to configure.</param>
    /// <returns>The same web application instance.</returns>
    public static WebApplication MapRecrovitOpenIdConnectEndpoints(this WebApplication app)
    {
        app.MapOidcAuthenticationEndpoints();
        return app;
    }
}
