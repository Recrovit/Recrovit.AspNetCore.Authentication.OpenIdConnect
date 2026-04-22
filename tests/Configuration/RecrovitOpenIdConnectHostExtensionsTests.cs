using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using System.Net;
using System.Net.WebSockets;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Configuration;

public sealed class RecrovitOpenIdConnectHostExtensionsTests
{
    [Fact]
    public void AddRecrovitOpenIdConnectInfrastructure_ReturnsSameBuilder_AndRegistersCoreServices()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });
        builder.Configuration.AddInMemoryCollection(TestConfiguration.CreateBaseConfiguration());

        var returnedBuilder = builder.AddRecrovitOpenIdConnectInfrastructure();

        using var serviceProvider = builder.Services.BuildServiceProvider();
        Assert.Same(builder, returnedBuilder);
        Assert.NotNull(serviceProvider.GetService<Microsoft.AspNetCore.Antiforgery.IAntiforgery>());
        Assert.NotNull(serviceProvider.GetService<IDownstreamUserTokenProvider>());
    }

    [Fact]
    public async Task UseRecrovitOpenIdConnectForwardedHeaders_AppliesConfiguredForwardedHeaders()
    {
        await using var app = await CreateForwardedHeadersApplicationAsync(new HostSecurityOptions
        {
            ForwardedHeadersEnabled = true,
            KnownProxies = ["127.0.0.1"]
        });
        using var client = app.GetTestClient();
        var request = new HttpRequestMessage(HttpMethod.Get, "/ip");
        request.Headers.Add("X-Forwarded-For", "203.0.113.10");

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal("203.0.113.10", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task UseRecrovitOpenIdConnectStatusCodePagesWithReExecute_Preserves404Behavior_ForProxyAndNonProxyRequests()
    {
        await using var app = await CreateStatusCodePagesApplicationAsync();
        using var client = app.GetTestClient();

        using var nonProxyResponse = await client.GetAsync("/non-proxy", TestContext.Current.CancellationToken);
        using var proxyResponse = await client.GetAsync("/proxy/session/check", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, nonProxyResponse.StatusCode);
        Assert.Equal(string.Empty, await nonProxyResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(HttpStatusCode.NotFound, proxyResponse.StatusCode);
        Assert.Equal(string.Empty, await proxyResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task UseRecrovitOpenIdConnectProxyTransports_EnablesWebSocketRequests()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.UseRecrovitOpenIdConnectProxyTransports();
        app.Map("/ws", async context =>
        {
            var feature = context.Features.Get<IHttpWebSocketFeature>();
            Assert.NotNull(feature);
            Assert.True(context.WebSockets.IsWebSocketRequest);

            _ = await context.WebSockets.AcceptWebSocketAsync();
        });

        await app.StartAsync(TestContext.Current.CancellationToken);

        var client = app.GetTestServer().CreateWebSocketClient();
        using var socket = await client.ConnectAsync(new Uri("ws://localhost/ws"), TestContext.Current.CancellationToken);

        Assert.Equal(WebSocketState.Open, socket.State);
    }

    [Fact]
    public async Task MapRecrovitOpenIdConnectEndpoints_MapsConfiguredAuthenticationEndpoints()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Host:EndpointBasePath"] = "/oidc"
        });
        await using var app = await CreateHostApplicationAsync(configuration, mapBuiltInEndpoints: true);
        using var client = app.GetTestClient();

        using var mappedResponse = await client.GetAsync("/oidc/logout", TestContext.Current.CancellationToken);
        using var unmappedResponse = await client.GetAsync("/authentication/logout", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, mappedResponse.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unmappedResponse.StatusCode);
    }

    private static async Task<WebApplication> CreateForwardedHeadersApplicationAsync(HostSecurityOptions hostSecurityOptions)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Services.AddLogging();
        builder.Services.AddSingleton<IOptions<HostSecurityOptions>>(Options.Create(hostSecurityOptions));

        var app = builder.Build();
        app.UseRecrovitOpenIdConnectForwardedHeaders();
        app.MapGet("/ip", (HttpContext context) => context.Connection.RemoteIpAddress?.ToString() ?? "none");

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<WebApplication> CreateStatusCodePagesApplicationAsync()
    {
        var configuration = TestConfiguration.Build();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Configuration.AddConfiguration(configuration);
        builder.AddRecrovitOpenIdConnectInfrastructure();

        var app = builder.Build();
        app.UseRouting();
        app.UseRecrovitOpenIdConnectStatusCodePagesWithReExecute("/errors/not-found");
        app.MapGet("/errors/not-found", () => Results.Text("re-executed", statusCode: StatusCodes.Status404NotFound));
        app.MapGet("/proxy/{**catchall}", () => Results.NotFound()).AsProxyEndpoint();
        app.Run(context =>
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return Task.CompletedTask;
        });

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<WebApplication> CreateHostApplicationAsync(IConfiguration configuration, bool mapBuiltInEndpoints)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Configuration.AddConfiguration(configuration);
        builder.AddRecrovitOpenIdConnectInfrastructure();

        var app = builder.Build();
        app.UseRecrovitOpenIdConnectAuthentication();
        if (mapBuiltInEndpoints)
        {
            app.MapRecrovitOpenIdConnectEndpoints();
        }

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }
}
