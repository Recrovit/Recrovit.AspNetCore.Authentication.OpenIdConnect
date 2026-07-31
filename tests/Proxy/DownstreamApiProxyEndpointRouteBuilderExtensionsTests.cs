using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Proxy;

public sealed class DownstreamApiProxyEndpointRouteBuilderExtensionsTests
{
    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_ProxiesConfiguredApiRequests()
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(() => new HttpResponseMessage(HttpStatusCode.Accepted)
        {
            Content = new StringContent(string.Empty)
        });
        var transportProxyClient = new RecordingDownstreamTransportProxyClient();

        await using var app = await CreateApplicationAsync(proxyClient, transportProxyClient);
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/downstream/GraphApi/me?expand=roles", TestContext.Current.CancellationToken);
        using var emptyPathResponse = await client.GetAsync("/downstream/GraphApi?expand=roles", TestContext.Current.CancellationToken);
        using var absolutePathResponse = await client.GetAsync("/downstream/GraphApi/https://attacker.example/collect", TestContext.Current.CancellationToken);
        using var schemeRelativeResponse = await client.GetAsync("/downstream/GraphApi/%2F%2Fattacker.example/collect", TestContext.Current.CancellationToken);
        using var backslashAuthorityResponse = await client.GetAsync("/downstream/GraphApi/%5C%5Cattacker.example%5Ccollect", TestContext.Current.CancellationToken);
        using var webSocketInvalidResponse = await client.GetAsync("/downstream/GraphApi/https://attacker.example/socket?ws=true", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, emptyPathResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, absolutePathResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, schemeRelativeResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, backslashAuthorityResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, webSocketInvalidResponse.StatusCode);
        Assert.Equal("GraphApi", proxyClient.DownstreamApiName);
        Assert.Equal(HttpMethod.Get, proxyClient.Method);
        Assert.Equal("?expand=roles", proxyClient.PathAndQuery);
        Assert.Equal(2, proxyClient.CallCount);
        Assert.Equal(0, transportProxyClient.CallCount);
    }

    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_ReturnsNotFound_ForUnknownApi()
    {
        await using var app = await CreateApplicationAsync(new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        }));
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/downstream/UnknownApi/me", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static async Task<WebApplication> CreateApplicationAsync(
        IDownstreamHttpProxyClient proxyClient,
        IDownstreamTransportProxyClient? transportProxyClient = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton(TestFactories.CreateDownstreamApiCatalog(relativePath: string.Empty));
        builder.Services.Replace(ServiceDescriptor.Singleton<IDownstreamHttpProxyClient>(proxyClient));
        builder.Services.Replace(ServiceDescriptor.Singleton<IDownstreamTransportProxyClient>(transportProxyClient ?? new NoOpDownstreamTransportProxyClient()));

        var app = builder.Build();
        app.Use(static (context, next) =>
        {
            context.User = TestUsers.CreateAuthenticatedUser();
            return next(context);
        });
        app.Use(static (context, next) =>
        {
            if (context.Request.Query.ContainsKey("ws"))
            {
                context.Features.Set<IHttpWebSocketFeature>(new TestWebSocketFeature());
            }

            return next(context);
        });
        app.UseAuthorization();
        app.MapDownstreamApiProxyEndpoints();

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private sealed class NoOpDownstreamTransportProxyClient : IDownstreamTransportProxyClient
    {
        public Task ProxyWebSocketAsync(HttpContext context, string downstreamApiName, string pathAndQuery, System.Security.Claims.ClaimsPrincipal? user, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    private sealed class TestWebSocketFeature : IHttpWebSocketFeature
    {
        public bool IsWebSocketRequest => true;

        public Task<System.Net.WebSockets.WebSocket> AcceptAsync(WebSocketAcceptContext context)
            => throw new NotSupportedException();
    }
}
