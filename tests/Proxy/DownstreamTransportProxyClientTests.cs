using System.Net;
using System.Net.WebSockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Proxy;

public sealed class DownstreamTransportProxyClientTests
{
    [Fact]
    public async Task ProxyWebSocketAsync_ForwardsHandshakeHeadersBearerTokenSubProtocolAndFrames()
    {
        await using var downstreamHost = await DownstreamWebSocketHost.StartAsync();
        await using var proxyApp = await CreateProxyApplicationAsync(downstreamHost.BaseAddress);
        var client = proxyApp.GetTestServer().CreateWebSocketClient();
        client.ConfigureRequest = request =>
        {
            request.Headers["Origin"] = "http://localhost";
            request.Headers["X-Client-Request-Id"] = "request-7";
            request.Headers["Accept-Language"] = "hu-HU";
        };
        client.SubProtocols.Add("recrovit.chat.v1");

        using var socket = await client.ConnectAsync(new Uri("ws://localhost/downstream/GraphApi/socket?trace=1"), TestContext.Current.CancellationToken);
        await SendTextAsync(socket, "ping", TestContext.Current.CancellationToken);

        var response = await ReceiveTextAsync(socket, TestContext.Current.CancellationToken);

        Assert.Equal("echo:ping", response);
        Assert.Equal("/socket?trace=1", downstreamHost.RequestPathAndQuery);
        Assert.Equal("recrovit.chat.v1", downstreamHost.RequestedSubProtocol);
        Assert.Equal("Bearer access-token", downstreamHost.Headers["Authorization"]);
        Assert.Equal("request-7", downstreamHost.Headers["X-Client-Request-Id"]);
        Assert.Equal("hu-HU", downstreamHost.Headers["Accept-Language"]);
    }

    [Fact]
    public async Task ProxyWebSocketAsync_LogsMaskedPath_WhenRequestIsNotWebSocket()
    {
        var logger = new ListLogger<DownstreamTransportProxyClient>();
        var client = new DownstreamTransportProxyClient(
            logger,
            new StubDownstreamUserTokenProvider(),
            TestFactories.CreateDownstreamApiCatalog(relativePath: "gateway"));
        var context = new DefaultHttpContext();

        await client.ProxyWebSocketAsync(
            context,
            "SessionValidationApi",
            "/session/check?access_token=secret&state=opaque",
            user: null,
            CancellationToken.None);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

        var warning = Assert.Single(logger.Entries, static entry => entry.Level == LogLevel.Warning);
        Assert.Contains("/session/check?access_token=***&state=***", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("secret", warning.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("opaque", warning.Message, StringComparison.Ordinal);
    }

    private static async Task<WebApplication> CreateProxyApplicationAsync(Uri downstreamBaseAddress)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Services.AddLogging();
        builder.Services.AddAuthorization();
        builder.Services.AddAntiforgery();
        builder.Services.AddSingleton(new DownstreamApiCatalog(new Dictionary<string, DownstreamApiDefinition>(StringComparer.OrdinalIgnoreCase)
        {
            ["GraphApi"] = new()
            {
                BaseUrl = downstreamBaseAddress.AbsoluteUri,
                Scopes = ["graph.read"],
                ForwardedRequestHeaders = ["X-Client-Request-Id", "Accept-Language"]
            }
        }));
        builder.Services.AddSingleton<IOptions<OidcAuthenticationOptions>>(Options.Create(new OidcAuthenticationOptions
        {
            DownstreamProxyRequestProtection = new DownstreamProxyRequestProtectionOptions
            {
                AllowedWebSocketOrigins = ["http://localhost"]
            }
        }));
        builder.Services.AddSingleton<IDownstreamUserTokenProvider>(new StubDownstreamUserTokenProvider());
        builder.Services.AddScoped<IDownstreamTransportProxyClient, DownstreamTransportProxyClient>();
        builder.Services.Replace(ServiceDescriptor.Singleton<IDownstreamHttpProxyClient>(
            new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK))));

        var proxyAssembly = typeof(IDownstreamHttpProxyClient).Assembly;
        var evaluatorInterface = proxyAssembly.GetType("Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy.IDownstreamProxyRequestProtectionEvaluator")
            ?? throw new InvalidOperationException("The downstream proxy request protection evaluator interface could not be found.");
        var evaluatorType = proxyAssembly.GetType("Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy.DownstreamProxyRequestProtectionEvaluator")
            ?? throw new InvalidOperationException("The downstream proxy request protection evaluator type could not be found.");
        builder.Services.AddSingleton(evaluatorInterface, evaluatorType);

        var app = builder.Build();
        app.UseWebSockets();
        app.Use((context, next) =>
        {
            context.User = TestUsers.CreateAuthenticatedUser();
            return next(context);
        });
        app.UseAuthorization();
        app.UseAntiforgery();
        app.MapDownstreamApiProxyEndpoints();

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task SendTextAsync(WebSocket socket, string message, CancellationToken cancellationToken)
    {
        var buffer = Encoding.UTF8.GetBytes(message);
        await socket.SendAsync(buffer, WebSocketMessageType.Text, endOfMessage: true, cancellationToken);
    }

    private static async Task<string> ReceiveTextAsync(WebSocket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        var result = await socket.ReceiveAsync(buffer, cancellationToken);
        Assert.Equal(WebSocketMessageType.Text, result.MessageType);
        Assert.True(result.EndOfMessage);
        return Encoding.UTF8.GetString(buffer, 0, result.Count);
    }

    private sealed class DownstreamWebSocketHost : IAsyncDisposable
    {
        private readonly WebApplication app;

        private DownstreamWebSocketHost(WebApplication app)
        {
            this.app = app;
        }

        public Uri BaseAddress { get; private set; } = null!;

        public string? RequestPathAndQuery { get; private set; }

        public string? RequestedSubProtocol { get; private set; }

        public IReadOnlyDictionary<string, string> Headers { get; private set; } =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static async Task<DownstreamWebSocketHost> StartAsync()
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = Environments.Development
            });
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));

            var host = new DownstreamWebSocketHost(builder.Build());
            host.app.UseWebSockets();
            host.app.Map("/socket", async context =>
            {
                host.RequestPathAndQuery = $"{context.Request.Path}{context.Request.QueryString}";
                host.RequestedSubProtocol = context.WebSockets.WebSocketRequestedProtocols.SingleOrDefault();
                host.Headers = context.Request.Headers.ToDictionary(
                    static header => header.Key,
                    static header => header.Value.ToString(),
                    StringComparer.OrdinalIgnoreCase);

                using var socket = await context.WebSockets.AcceptWebSocketAsync(host.RequestedSubProtocol);
                var buffer = new byte[1024];
                var result = await socket.ReceiveAsync(buffer, TestContext.Current.CancellationToken);
                var message = Encoding.UTF8.GetString(buffer, 0, result.Count);
                await socket.SendAsync(
                    Encoding.UTF8.GetBytes($"echo:{message}"),
                    WebSocketMessageType.Text,
                    endOfMessage: true,
                    TestContext.Current.CancellationToken);
                await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "done", TestContext.Current.CancellationToken);
            });

            await host.app.StartAsync(TestContext.Current.CancellationToken);
            host.BaseAddress = new Uri(host.app.Urls.Single(), UriKind.Absolute);
            return host;
        }

        public async ValueTask DisposeAsync()
        {
            await app.DisposeAsync();
        }
    }
}
