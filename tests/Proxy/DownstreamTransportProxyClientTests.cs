using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Proxy;

public sealed class DownstreamTransportProxyClientTests
{
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
}
