using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

/// <summary>
/// Maps generic proxy endpoints for configured downstream APIs.
/// </summary>
public static class DownstreamApiProxyEndpointRouteBuilderExtensions
{
    public const string DefaultRoutePrefix = "/downstream";

    public static IEndpointRouteBuilder MapDownstreamApiProxyEndpoints(this IEndpointRouteBuilder endpoints, string routePrefix = DefaultRoutePrefix)
        => endpoints.MapDownstreamApiProxyEndpoints(static _ => { }, routePrefix);

    public static IEndpointRouteBuilder MapDownstreamApiProxyEndpoints(
        this IEndpointRouteBuilder endpoints,
        Action<DownstreamProxyEndpointOptions> configure,
        string routePrefix = DefaultRoutePrefix)
    {
        var normalizedRoutePrefix = NormalizeRoutePrefix(routePrefix);
        var options = new DownstreamProxyEndpointOptions();
        configure(options);
        var metadata = options.Build(
            endpoints.ServiceProvider.GetRequiredService<DownstreamApiCatalog>(),
            normalizedRoutePrefix);

        endpoints.MapMethods(
                $"{normalizedRoutePrefix}/{{apiName}}",
                ProxyEndpointConventionBuilderExtensions.DownstreamProxyMethods,
                ProxyDownstreamApiAsync)
            .WithMetadata(metadata)
            .WithMetadata(new RequireAntiforgeryTokenAttribute())
            .AsProxyEndpoint()
            .RequireAuthorization()
            .DisableAuthRedirects()
            .WithSummary("Proxies requests to a configured downstream API.");

        endpoints.MapMethods(
                $"{normalizedRoutePrefix}/{{apiName}}/{{**path}}",
                ProxyEndpointConventionBuilderExtensions.DownstreamProxyMethods,
                ProxyDownstreamApiAsync)
            .WithMetadata(metadata)
            .WithMetadata(new RequireAntiforgeryTokenAttribute())
            .AsProxyEndpoint()
            .RequireAuthorization()
            .DisableAuthRedirects()
            .WithSummary("Proxies requests to a configured downstream API.");

        return endpoints;
    }

    private static async Task<IResult> ProxyDownstreamApiAsync(
        HttpContext context,
        string apiName,
        string? path,
        DownstreamApiCatalog downstreamApiCatalog,
        IDownstreamProxyRequestProtectionEvaluator requestProtectionEvaluator,
        IAntiforgery antiforgery,
        IDownstreamHttpProxyClient httpProxyClient,
        IDownstreamTransportProxyClient transportProxyClient,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        if (!downstreamApiCatalog.Apis.ContainsKey(apiName))
        {
            return Results.NotFound();
        }

        var protectionEvaluation = requestProtectionEvaluator.Evaluate(context);
        if (!protectionEvaluation.IsAllowed)
        {
            return Results.StatusCode(protectionEvaluation.FailureStatusCode);
        }

        if (protectionEvaluation.RequiresAntiforgeryValidation
            && !await IsAntiforgeryRequestValidAsync(context, antiforgery, loggerFactory))
        {
            return Results.BadRequest();
        }

        var pathAndQuery = BuildPathAndQuery(path, context.Request.QueryString);
        var downstreamApi = downstreamApiCatalog.GetRequired(apiName);

        try
        {
            DownstreamProxyUtilities.ValidateDownstreamPath(downstreamApi, pathAndQuery);

            if (context.WebSockets.IsWebSocketRequest)
            {
                await transportProxyClient.ProxyWebSocketAsync(context, apiName, pathAndQuery, context.User, cancellationToken);
                return Results.Empty;
            }

            await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
                context,
                httpProxyClient,
                downstreamApiCatalog,
                apiName,
                pathAndQuery,
                context.User,
                cancellationToken);

            return Results.Empty;
        }
        catch (InvalidDownstreamProxyPathException)
        {
            return Results.BadRequest();
        }
    }

    private static string NormalizeRoutePrefix(string routePrefix)
    {
        var normalized = string.IsNullOrWhiteSpace(routePrefix)
            ? DefaultRoutePrefix
            : routePrefix.Trim();

        if (!normalized.StartsWith('/'))
        {
            normalized = "/" + normalized;
        }

        return normalized.TrimEnd('/');
    }

    private static string BuildPathAndQuery(string? path, QueryString queryString)
    {
        var normalizedPath = string.IsNullOrWhiteSpace(path)
            ? string.Empty
            : "/" + path.TrimStart('/');

        return $"{normalizedPath}{queryString}";
    }

    private static async Task<bool> IsAntiforgeryRequestValidAsync(
        HttpContext context,
        IAntiforgery antiforgery,
        ILoggerFactory loggerFactory)
    {
        var logger = loggerFactory.CreateLogger(typeof(DownstreamApiProxyEndpointRouteBuilderExtensions).FullName!);

        var antiforgeryValidationFeature = context.Features.Get<IAntiforgeryValidationFeature>();
        if (antiforgeryValidationFeature is { IsValid: false })
        {
            OidcProxyLog.DownstreamProxyRequestRejected(
                logger,
                context.Request.Path.Value ?? "/",
                context.Request.Method,
                "http",
                "antiforgery:feature");
            return false;
        }

        if (!await antiforgery.IsRequestValidAsync(context))
        {
            OidcProxyLog.DownstreamProxyRequestRejected(
                logger,
                context.Request.Path.Value ?? "/",
                context.Request.Method,
                "http",
                "antiforgery:service");
            return false;
        }

        return true;
    }
}
