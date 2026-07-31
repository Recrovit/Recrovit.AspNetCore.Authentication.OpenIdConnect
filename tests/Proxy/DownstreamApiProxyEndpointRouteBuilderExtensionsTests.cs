using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
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

        client.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-origin");
        using var response = await client.GetAsync("/downstream/GraphApi/me?expand=roles", TestContext.Current.CancellationToken);
        using var emptyPathResponse = await client.GetAsync("/downstream/GraphApi?expand=roles", TestContext.Current.CancellationToken);
        using var absolutePathResponse = await client.GetAsync("/downstream/GraphApi/https://attacker.example/collect", TestContext.Current.CancellationToken);
        using var schemeRelativeResponse = await client.GetAsync("/downstream/GraphApi/%2F%2Fattacker.example/collect", TestContext.Current.CancellationToken);
        using var backslashAuthorityResponse = await client.GetAsync("/downstream/GraphApi/%5C%5Cattacker.example%5Ccollect", TestContext.Current.CancellationToken);
        using var portSwitchResponse = await client.GetAsync("/downstream/PortApi/https://api.example.com:444/collect", TestContext.Current.CancellationToken);
        using var webSocketInvalidResponse = await client.GetAsync("/downstream/GraphApi/https://attacker.example/socket?ws=true", TestContext.Current.CancellationToken);
        using var webSocketEncodedSeparatorResponse = await client.GetAsync("/downstream/GraphApi/%2F%2Fattacker.example/socket?ws=true", TestContext.Current.CancellationToken);
        using var webSocketBackslashResponse = await client.GetAsync("/downstream/GraphApi/%5C%5Cattacker.example%5Csocket?ws=true", TestContext.Current.CancellationToken);
        using var webSocketPortSwitchResponse = await client.GetAsync("/downstream/PortApi/https://api.example.com:444/socket?ws=true", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, emptyPathResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, absolutePathResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, schemeRelativeResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, backslashAuthorityResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, portSwitchResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, webSocketInvalidResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, webSocketEncodedSeparatorResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, webSocketBackslashResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, webSocketPortSwitchResponse.StatusCode);
        Assert.Equal("GraphApi", proxyClient.DownstreamApiName);
        Assert.Equal(HttpMethod.Get, proxyClient.Method);
        Assert.Equal("?expand=roles", proxyClient.PathAndQuery);
        Assert.Equal(2, proxyClient.CallCount);
        Assert.Equal(0, transportProxyClient.CallCount);
    }

    [Theory]
    [InlineData("/downstream/GraphApi/%252e%252e/admin")]
    [InlineData("/downstream/GraphApi/..%2fadmin")]
    [InlineData("/downstream/GraphApi/..%5cadmin")]
    public async Task MapDownstreamApiProxyEndpoints_ReturnsBadRequest_ForTraversalPayloads(string requestPath)
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });
        var transportProxyClient = new RecordingDownstreamTransportProxyClient();

        await using var app = await CreateApplicationAsync(proxyClient, transportProxyClient);
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-origin");

        using var response = await client.GetAsync(requestPath, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, proxyClient.CallCount);
        Assert.Equal(0, transportProxyClient.CallCount);
    }

    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_ReturnsBadRequest_ForTraversalPayloadsOnWebSocketRequests()
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });
        var transportProxyClient = new RecordingDownstreamTransportProxyClient();

        await using var app = await CreateApplicationAsync(proxyClient, transportProxyClient);
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-origin");

        using var response = await client.GetAsync("/downstream/GraphApi/%252e%252e/socket?ws=true", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, proxyClient.CallCount);
        Assert.Equal(0, transportProxyClient.CallCount);
    }

    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_ConfinesRequestsToConfiguredRelativeRoot()
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });
        var catalog = new DownstreamApiCatalog(new Dictionary<string, DownstreamApiDefinition>(StringComparer.OrdinalIgnoreCase)
        {
            ["SessionValidationApi"] = new()
            {
                BaseUrl = "https://api.example.com",
                Scopes = ["openid"],
                RelativePath = "gateway/api"
            },
            ["GraphApi"] = new()
            {
                BaseUrl = "https://graph.example.com",
                Scopes = ["graph.read"],
                RelativePath = "gateway/api"
            }
        });

        await using var app = await CreateApplicationAsync(proxyClient, downstreamApiCatalog: catalog);
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-origin");

        using var acceptedResponse = await client.GetAsync("/downstream/GraphApi/users?id=7", TestContext.Current.CancellationToken);
        using var rejectedResponse = await client.GetAsync("/downstream/GraphApi/..%2fadmin", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, acceptedResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, rejectedResponse.StatusCode);
        Assert.Equal(1, proxyClient.CallCount);
        Assert.Equal("/users?id=7", proxyClient.PathAndQuery);
    }

    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_AllowsRequestsWithinConfiguredBasePath()
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });
        var catalog = new DownstreamApiCatalog(new Dictionary<string, DownstreamApiDefinition>(StringComparer.OrdinalIgnoreCase)
        {
            ["SessionValidationApi"] = new()
            {
                BaseUrl = "https://api.example.com/gateway",
                Scopes = ["openid"],
                RelativePath = string.Empty
            },
            ["GraphApi"] = new()
            {
                BaseUrl = "https://graph.example.com/gateway",
                Scopes = ["graph.read"],
                RelativePath = string.Empty
            }
        });

        await using var app = await CreateApplicationAsync(proxyClient, downstreamApiCatalog: catalog);
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("Sec-Fetch-Site", "same-origin");

        using var response = await client.GetAsync("/downstream/GraphApi/users?id=7", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, proxyClient.CallCount);
        Assert.Equal("/users?id=7", proxyClient.PathAndQuery);
    }

    [Theory]
    [InlineData("same-origin")]
    [InlineData("same-site")]
    [InlineData("none")]
    public async Task MapDownstreamApiProxyEndpoints_AllowsGet_WhenFetchMetadataAllowsIt(string fetchMetadataSite)
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });

        await using var app = await CreateApplicationAsync(proxyClient);
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("Sec-Fetch-Site", fetchMetadataSite);

        using var response = await client.GetAsync("/downstream/GraphApi/me", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, proxyClient.CallCount);
    }

    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_RejectsCrossSiteGet_WhenFetchMetadataIndicatesCrossSite()
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });

        await using var app = await CreateApplicationAsync(proxyClient);
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("Sec-Fetch-Site", "cross-site");

        using var response = await client.GetAsync("/downstream/GraphApi/me", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, proxyClient.CallCount);
    }

    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_AllowsGet_WhenOriginFallbackMatchesCurrentOrigin()
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });

        await using var app = await CreateApplicationAsync(proxyClient);
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("Origin", "http://localhost");

        using var response = await client.GetAsync("/downstream/GraphApi/me", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, proxyClient.CallCount);
    }

    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_AllowsGet_WhenCustomHeaderFallbackMatches()
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });

        await using var app = await CreateApplicationAsync(
            proxyClient,
            protectionOptions: new DownstreamProxyGetProtectionOptions
            {
                CustomHeaderName = "X-Recrovit-Proxy-Intent",
                CustomHeaderValue = "same-site"
            });
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("X-Recrovit-Proxy-Intent", "same-site");

        using var response = await client.GetAsync("/downstream/GraphApi/me", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, proxyClient.CallCount);
    }

    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_RejectsGet_WhenFallbackSignalsAreMissing()
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });

        await using var app = await CreateApplicationAsync(
            proxyClient,
            protectionOptions: new DownstreamProxyGetProtectionOptions
            {
                CustomHeaderName = "X-Recrovit-Proxy-Intent",
                CustomHeaderValue = "same-site"
            });
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/downstream/GraphApi/me", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, proxyClient.CallCount);
    }

    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_LeavesPostUnchanged_WhenFetchMetadataIsCrossSite()
    {
        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.Accepted)
        {
            Content = new StringContent(string.Empty)
        });

        await using var app = await CreateApplicationAsync(proxyClient);
        using var client = app.GetTestClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/downstream/GraphApi/me");
        request.Headers.Add("Sec-Fetch-Site", "cross-site");
        request.Content = new StringContent("""{"message":"hello"}""");

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(1, proxyClient.CallCount);
        Assert.Equal(HttpMethod.Post, proxyClient.Method);
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
        IDownstreamTransportProxyClient? transportProxyClient = null,
        DownstreamProxyGetProtectionOptions? protectionOptions = null,
        DownstreamApiCatalog? downstreamApiCatalog = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Services.AddAuthorization();
        builder.Services.AddSingleton(downstreamApiCatalog ?? new DownstreamApiCatalog(new Dictionary<string, DownstreamApiDefinition>(StringComparer.OrdinalIgnoreCase)
        {
            ["SessionValidationApi"] = new()
            {
                BaseUrl = "https://api.example.com",
                Scopes = ["openid"],
                RelativePath = string.Empty
            },
            ["GraphApi"] = new()
            {
                BaseUrl = "https://graph.example.com",
                Scopes = ["graph.read"],
                RelativePath = string.Empty
            },
            ["PortApi"] = new()
            {
                BaseUrl = "https://api.example.com:443",
                Scopes = ["openid"],
                RelativePath = string.Empty
            }
        }));
        builder.Services.AddSingleton<IOptions<OidcAuthenticationOptions>>(Options.Create(new OidcAuthenticationOptions
        {
            DownstreamProxyGetProtection = protectionOptions ?? new DownstreamProxyGetProtectionOptions()
        }));
        var proxyAssembly = typeof(IDownstreamHttpProxyClient).Assembly;
        var evaluatorInterface = proxyAssembly.GetType("Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy.IDownstreamProxyGetRequestProtectionEvaluator")
            ?? throw new InvalidOperationException("The downstream proxy GET request protection evaluator interface could not be found.");
        var evaluatorType = proxyAssembly.GetType("Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy.DownstreamProxyGetRequestProtectionEvaluator")
            ?? throw new InvalidOperationException("The downstream proxy GET request protection evaluator type could not be found.");
        builder.Services.AddSingleton(evaluatorInterface, evaluatorType);
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
