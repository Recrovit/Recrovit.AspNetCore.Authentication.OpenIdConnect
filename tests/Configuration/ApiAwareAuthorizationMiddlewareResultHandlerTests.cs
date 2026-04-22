using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Configuration;

public sealed class ApiAwareAuthorizationMiddlewareResultHandlerTests
{
    [Fact]
    public async Task ProtectedApiEndpoint_Returns401InsteadOfRedirect()
    {
        await using var app = await CreateApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync($"{OidcAuthenticationConstants.RequestPaths.ApiPrefix}/userinfo", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Location"));
    }

    [Fact]
    public async Task ProtectedJsonEndpoint_Returns401InsteadOfRedirect()
    {
        await using var app = await CreateApplicationAsync();
        using var client = app.GetTestClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/userinfo");
        request.Headers.Accept.ParseAdd(OidcAuthenticationConstants.MediaTypes.Json);

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Location"));
    }

    [Fact]
    public async Task ProtectedProxyEndpoint_Returns401InsteadOfRedirect()
    {
        await using var app = await CreateApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/proxy/session/check", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Location"));
    }

    [Fact]
    public async Task ProtectedPage_DelegatesToDefaultRedirectBehavior()
    {
        await using var app = await CreateApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/page", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.NotNull(response.Headers.Location);
    }

    [Fact]
    public async Task DisableAuthRedirectsEndpoint_Returns403ForForbiddenUsers()
    {
        var forbiddenUser = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "user-123"),
            new Claim(ClaimTypes.Name, "Ada")
        ],
        authenticationType: "test"));

        await using var app = await CreateApplicationAsync(authenticatedUser: forbiddenUser);
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/reports", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("Location"));
    }

    private static async Task<WebApplication> CreateApplicationAsync(ClaimsPrincipal? authenticatedUser = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(TestConfiguration.CreateBaseConfiguration());
        builder.AddRecrovitOpenIdConnectInfrastructure();
        builder.Services.Replace(ServiceDescriptor.Singleton<IAuthenticationService, RedirectingAuthenticationService>());
        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("AdminOnly", policy => policy.RequireClaim(ClaimTypes.Role, "Admin"));
        });

        var app = builder.Build();
        if (authenticatedUser is not null)
        {
            app.Use((httpContext, next) =>
            {
                httpContext.User = authenticatedUser;
                return next(httpContext);
            });
        }

        app.UseRecrovitOpenIdConnectAuthentication();
        app.MapGet($"{OidcAuthenticationConstants.RequestPaths.ApiPrefix}/userinfo", static () => Results.Ok()).RequireAuthorization();
        app.MapGet("/userinfo", static () => Results.Ok()).RequireAuthorization();
        app.MapGet("/proxy/session/check", static () => Results.Ok()).AsProxyEndpoint().RequireAuthorization();
        app.MapGet("/page", static () => Results.Ok()).RequireAuthorization();
        app.MapGet("/reports", static () => Results.Ok())
            .DisableAuthRedirects()
            .RequireAuthorization("AdminOnly");
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }
}
