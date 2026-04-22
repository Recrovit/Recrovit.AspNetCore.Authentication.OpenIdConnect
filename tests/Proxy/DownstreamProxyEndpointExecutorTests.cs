using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Proxy;

public sealed class DownstreamProxyEndpointExecutorTests
{
    [Fact]
    public async Task ProxyHttpAsync_ForwardsPostRequestContentAndWritesFilteredResponse()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/gateway/session/check";
        context.Request.QueryString = new QueryString("?page=2");
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.Headers["Accept-Language"] = "hu-HU";
        context.Request.ContentLength = 18;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{"message":"hello"}"""));
        context.Response.Body = new MemoryStream();

        var downstreamResponse = new HttpResponseMessage(HttpStatusCode.Accepted)
        {
            Content = new StringContent("""{"status":"ok"}""", Encoding.UTF8, OidcAuthenticationConstants.MediaTypes.Json)
        };
        downstreamResponse.Headers.TryAddWithoutValidation("X-Trace-Id", "trace-123");
        downstreamResponse.Headers.TransferEncodingChunked = true;
        downstreamResponse.Content.Headers.ContentLanguage.Add("hu");

        var proxyClient = new RecordingDownstreamHttpProxyClient(downstreamResponse);
        var user = TestUsers.CreateAuthenticatedUser();

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            "SessionValidationApi",
            user,
            CancellationToken.None);

        Assert.Equal("SessionValidationApi", proxyClient.DownstreamApiName);
        Assert.Equal(HttpMethod.Post, proxyClient.Method);
        Assert.Equal("/gateway/session/check?page=2", proxyClient.PathAndQuery);
        Assert.Same(user, proxyClient.User);
        Assert.Equal(OidcAuthenticationConstants.MediaTypes.Json, proxyClient.ContentType);
        Assert.Equal("""{"message":"hello"}""", proxyClient.ContentBody);
        Assert.Contains(proxyClient.Headers, static header => header.Key == "Accept-Language" && header.Value == "hu-HU");

        Assert.Equal(StatusCodes.Status202Accepted, context.Response.StatusCode);
        Assert.Equal("trace-123", context.Response.Headers["X-Trace-Id"]);
        Assert.Equal("hu", context.Response.Headers["Content-Language"]);
        Assert.False(context.Response.Headers.ContainsKey("transfer-encoding"));

        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, Encoding.UTF8, leaveOpen: true);
        Assert.Equal("""{"status":"ok"}""", await reader.ReadToEndAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ProxyHttpAsync_DoesNotCreateContent_ForGetRequestOrEmptyBody()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = "/gateway/session/check";
        context.Request.QueryString = QueryString.Empty;
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.ContentLength = 0;
        context.Request.Body = new MemoryStream();
        context.Response.Body = new MemoryStream();

        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            "SessionValidationApi",
            user: null,
            CancellationToken.None);

        Assert.Equal(HttpMethod.Get, proxyClient.Method);
        Assert.Null(proxyClient.ContentType);
        Assert.Null(proxyClient.ContentBody);
    }

    [Fact]
    public async Task ProxyHttpAsync_ForwardsPutRequestContent()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Put;
        context.Request.Path = "/gateway/session/check";
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.ContentLength = 15;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{"status":"ok"}"""));
        context.Response.Body = new MemoryStream();

        var proxyClient = new RecordingDownstreamHttpProxyClient(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        });

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            "SessionValidationApi",
            user: null,
            CancellationToken.None);

        Assert.Equal(HttpMethod.Put, proxyClient.Method);
        Assert.Equal("""{"status":"ok"}""", proxyClient.ContentBody);
    }
}
