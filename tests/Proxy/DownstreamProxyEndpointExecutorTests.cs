using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Proxy;

public sealed class DownstreamProxyEndpointExecutorTests
{
    [Fact]
    public async Task ProxyHttpAsync_ForwardsPostRequestContentAndWritesFilteredResponse()
    {
        var context = CreateContext(HttpMethods.Post);
        context.Request.Path = "/gateway/session/check";
        context.Request.QueryString = new QueryString("?page=2");
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.Headers["Accept-Language"] = "hu-HU";
        context.Request.Headers["Content-Encoding"] = "gzip";
        context.Request.Headers["Content-Language"] = "hu, en";
        context.Request.ContentLength = 19;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{"message":"hello"}"""));
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new StubRequestBodyDetectionFeature(canHaveBody: true));

        var downstreamResponse = new HttpResponseMessage(HttpStatusCode.Accepted)
        {
            Content = new StringContent("""{"status":"ok"}""", Encoding.UTF8, OidcAuthenticationConstants.MediaTypes.Json)
        };
        downstreamResponse.Headers.TryAddWithoutValidation("X-Trace-Id", "trace-123");
        downstreamResponse.Headers.TryAddWithoutValidation("Set-Cookie", "__Host-Auth=attacker; Secure; Path=/");
        downstreamResponse.Headers.TryAddWithoutValidation("Connection", "keep-alive, x-hop-header");
        downstreamResponse.Headers.TryAddWithoutValidation("Keep-Alive", "timeout=5");
        downstreamResponse.Headers.TryAddWithoutValidation("Upgrade", "websocket");
        downstreamResponse.Headers.TryAddWithoutValidation("X-Hop-Header", "blocked");
        downstreamResponse.Headers.TransferEncodingChunked = true;
        downstreamResponse.Content.Headers.ContentLanguage.Add("hu");
        downstreamResponse.Content.Headers.TryAddWithoutValidation("Trailer", "Expires");

        var proxyClient = new RecordingDownstreamHttpProxyClient(downstreamResponse);
        var downstreamApiCatalog = CreateDownstreamApiCatalog();
        var user = TestUsers.CreateAuthenticatedUser();

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            downstreamApiCatalog,
            "SessionValidationApi",
            "/gateway/session/check?page=2",
            user,
            CancellationToken.None);

        Assert.Equal("SessionValidationApi", proxyClient.DownstreamApiName);
        Assert.Equal(HttpMethod.Post, proxyClient.Method);
        Assert.Equal("/gateway/session/check?page=2", proxyClient.PathAndQuery);
        Assert.Same(user, proxyClient.User);
        Assert.Equal(OidcAuthenticationConstants.MediaTypes.Json, proxyClient.ContentType);
        Assert.Equal("""{"message":"hello"}""", proxyClient.ContentBody);
        Assert.Contains(proxyClient.Headers, static header => header.Key == "Accept-Language" && header.Value == "hu-HU");
        Assert.Equal(["gzip"], proxyClient.ContentHeaders["Content-Encoding"]);
        Assert.Equal(["hu", "en"], proxyClient.ContentHeaders["Content-Language"]);
        Assert.DoesNotContain(proxyClient.Headers, static header => string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase));

        Assert.Equal(StatusCodes.Status202Accepted, context.Response.StatusCode);
        Assert.Equal("trace-123", context.Response.Headers["X-Trace-Id"]);
        Assert.Equal("hu", context.Response.Headers["Content-Language"]);
        Assert.False(context.Response.Headers.ContainsKey("Set-Cookie"));
        Assert.False(context.Response.Headers.ContainsKey("Connection"));
        Assert.False(context.Response.Headers.ContainsKey("Keep-Alive"));
        Assert.False(context.Response.Headers.ContainsKey("Upgrade"));
        Assert.False(context.Response.Headers.ContainsKey("Trailer"));
        Assert.False(context.Response.Headers.ContainsKey("X-Hop-Header"));
        Assert.False(context.Response.Headers.ContainsKey("transfer-encoding"));

        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, Encoding.UTF8, leaveOpen: true);
        Assert.Equal("""{"status":"ok"}""", await reader.ReadToEndAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ProxyHttpAsync_DoesNotCreateContent_ForGetRequest()
    {
        var context = CreateContext(HttpMethods.Get);
        context.Request.Path = "/gateway/session/check";
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{"message":"ignored"}"""));
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new StubRequestBodyDetectionFeature(canHaveBody: true));

        var proxyClient = new RecordingDownstreamHttpProxyClient(CreateEmptyResponse());
        var downstreamApiCatalog = TestFactories.CreateDownstreamApiCatalog(relativePath: string.Empty);

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            downstreamApiCatalog,
            "SessionValidationApi",
            "/gateway/session/check",
            user: null,
            CancellationToken.None);

        Assert.Equal(HttpMethod.Get, proxyClient.Method);
        Assert.Null(proxyClient.ContentType);
        Assert.Null(proxyClient.ContentBody);
        Assert.Empty(proxyClient.ContentHeaders);
    }

    [Fact]
    public async Task ProxyHttpAsync_DoesNotCreateContent_WhenBodyDetectionDisallowsBody()
    {
        var context = CreateContext(HttpMethods.Post);
        context.Request.Path = "/gateway/session/check";
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{"message":"ignored"}"""));
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new StubRequestBodyDetectionFeature(canHaveBody: false));

        var proxyClient = new RecordingDownstreamHttpProxyClient(CreateEmptyResponse());
        var downstreamApiCatalog = TestFactories.CreateDownstreamApiCatalog(relativePath: string.Empty);

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            downstreamApiCatalog,
            "SessionValidationApi",
            "/gateway/session/check",
            user: null,
            CancellationToken.None);

        Assert.Equal(HttpMethod.Post, proxyClient.Method);
        Assert.Null(proxyClient.ContentBody);
        Assert.Empty(proxyClient.ContentHeaders);
    }

    [Fact]
    public async Task ProxyHttpAsync_ForwardsPostRequestContent_WithoutContentLength_WhenBodyDetectionAllowsBody()
    {
        var context = CreateContext(HttpMethods.Post);
        context.Request.Path = "/gateway/session/check";
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{"status":"ok"}"""));
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new StubRequestBodyDetectionFeature(canHaveBody: true));

        var proxyClient = new RecordingDownstreamHttpProxyClient(CreateEmptyResponse());
        var downstreamApiCatalog = TestFactories.CreateDownstreamApiCatalog(relativePath: string.Empty);

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            downstreamApiCatalog,
            "SessionValidationApi",
            "/gateway/session/check",
            user: null,
            CancellationToken.None);

        Assert.Equal(HttpMethod.Post, proxyClient.Method);
        Assert.Equal("""{"status":"ok"}""", proxyClient.ContentBody);
    }

    [Theory]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    public async Task ProxyHttpAsync_ForwardsRequestContent_ForSupportedMethods(string method)
    {
        var context = CreateContext(method);
        context.Request.Path = "/gateway/session/check";
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{"status":"ok"}"""));
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new StubRequestBodyDetectionFeature(canHaveBody: true));

        var proxyClient = new RecordingDownstreamHttpProxyClient(CreateEmptyResponse());
        var downstreamApiCatalog = TestFactories.CreateDownstreamApiCatalog(relativePath: string.Empty);

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            downstreamApiCatalog,
            "SessionValidationApi",
            "/gateway/session/check",
            user: null,
            CancellationToken.None);

        Assert.Equal(new HttpMethod(method), proxyClient.Method);
        Assert.Equal("""{"status":"ok"}""", proxyClient.ContentBody);
    }

    [Fact]
    public async Task ProxyHttpAsync_ForwardsEmptyPostBody_WhenBodyDetectionAllowsBody()
    {
        var context = CreateContext(HttpMethods.Post);
        context.Request.Path = "/gateway/session/check";
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.Body = new MemoryStream();
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new StubRequestBodyDetectionFeature(canHaveBody: true));

        var proxyClient = new RecordingDownstreamHttpProxyClient(CreateEmptyResponse());
        var downstreamApiCatalog = TestFactories.CreateDownstreamApiCatalog(relativePath: string.Empty);

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            downstreamApiCatalog,
            "SessionValidationApi",
            "/gateway/session/check",
            user: null,
            CancellationToken.None);

        Assert.Equal(string.Empty, proxyClient.ContentBody);
        Assert.Equal(OidcAuthenticationConstants.MediaTypes.Json, proxyClient.ContentType);
    }

    [Fact]
    public async Task ProxyHttpAsync_UsesBodyDetectionFeature_ForHttp3CompatibleRequests()
    {
        var context = CreateContext(HttpMethods.Post);
        context.Request.Protocol = HttpProtocol.Http3;
        context.Request.Path = "/gateway/session/check";
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("""{"status":"http3"}"""));
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new StubRequestBodyDetectionFeature(canHaveBody: true));

        var proxyClient = new RecordingDownstreamHttpProxyClient(CreateEmptyResponse());
        var downstreamApiCatalog = TestFactories.CreateDownstreamApiCatalog(relativePath: string.Empty);

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            downstreamApiCatalog,
            "SessionValidationApi",
            "/gateway/session/check",
            user: null,
            CancellationToken.None);

        Assert.Equal("""{"status":"http3"}""", proxyClient.ContentBody);
    }

    [Fact]
    public async Task ProxyHttpAsync_StreamsLargeRequestBody()
    {
        var payload = string.Concat(Enumerable.Repeat("streaming-payload-", 8192));
        var bodyStream = new ChunkedReadStream(Encoding.UTF8.GetBytes(payload), 1024);
        var context = CreateContext(HttpMethods.Post);
        context.Request.Path = "/gateway/session/check";
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.Body = bodyStream;
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new StubRequestBodyDetectionFeature(canHaveBody: true));

        var proxyClient = new StreamingCaptureDownstreamHttpProxyClient();
        var downstreamApiCatalog = TestFactories.CreateDownstreamApiCatalog(relativePath: string.Empty);

        await DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            downstreamApiCatalog,
            "SessionValidationApi",
            "/gateway/session/check",
            user: null,
            CancellationToken.None);

        Assert.Equal(payload, proxyClient.ContentBody);
        Assert.True(bodyStream.ReadCount > 1);
        Assert.True(proxyClient.ReadCount > 1);
    }

    [Fact]
    public async Task ProxyHttpAsync_PropagatesCancellationWhileStreamingRequestBody()
    {
        var context = CreateContext(HttpMethods.Post);
        context.Request.Path = "/gateway/session/check";
        context.Request.ContentType = OidcAuthenticationConstants.MediaTypes.Json;
        context.Request.Body = new CancelableBlockingStream();
        context.Features.Set<IHttpRequestBodyDetectionFeature>(new StubRequestBodyDetectionFeature(canHaveBody: true));

        var proxyClient = new PassThroughStreamingDownstreamHttpProxyClient();
        var downstreamApiCatalog = TestFactories.CreateDownstreamApiCatalog(relativePath: string.Empty);
        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DownstreamProxyEndpointExecutor.ProxyHttpAsync(
            context,
            proxyClient,
            downstreamApiCatalog,
            "SessionValidationApi",
            "/gateway/session/check",
            user: null,
            cancellationTokenSource.Token));
    }

    private static DefaultHttpContext CreateContext(string method)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Response.Body = new MemoryStream();
        var downstreamApiCatalog = CreateDownstreamApiCatalog();
        context.RequestServices = new ServiceCollection()
            .AddLogging()
            .AddSingleton(downstreamApiCatalog)
            .BuildServiceProvider();
        return context;
    }

    private static DownstreamApiCatalog CreateDownstreamApiCatalog()
    {
        return new DownstreamApiCatalog(new Dictionary<string, DownstreamApiDefinition>(StringComparer.OrdinalIgnoreCase)
        {
            ["SessionValidationApi"] = new()
            {
                BaseUrl = "https://api.example.com",
                RelativePath = "gateway",
                Scopes = ["openid"],
                ForwardedRequestHeaders = ["Accept-Language"],
                ForwardedResponseHeaders = ["X-Trace-Id"]
            }
        });
    }

    private static HttpResponseMessage CreateEmptyResponse()
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent(string.Empty)
        };

    private sealed class StreamingCaptureDownstreamHttpProxyClient : IDownstreamHttpProxyClient
    {
        public int ReadCount { get; private set; }

        public string? ContentBody { get; private set; }

        public async Task<HttpResponseMessage> SendAsync(
            string downstreamApiName,
            HttpMethod method,
            string pathAndQuery,
            ClaimsPrincipal? user,
            HttpContent? content,
            IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>> headers,
            CancellationToken cancellationToken)
        {
            var requestContent = Assert.IsType<StreamContent>(content);

            using var reader = new StreamReader(await requestContent.ReadAsStreamAsync(cancellationToken), Encoding.UTF8, leaveOpen: true);
            var buffer = new char[2048];
            var builder = new StringBuilder();
            while (true)
            {
                var read = await reader.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
                if (read == 0)
                {
                    break;
                }

                ReadCount++;
                builder.Append(buffer, 0, read);
            }

            ContentBody = builder.ToString();

            return CreateEmptyResponse();
        }
    }

    private sealed class PassThroughStreamingDownstreamHttpProxyClient : IDownstreamHttpProxyClient
    {
        public async Task<HttpResponseMessage> SendAsync(
            string downstreamApiName,
            HttpMethod method,
            string pathAndQuery,
            ClaimsPrincipal? user,
            HttpContent? content,
            IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>> headers,
            CancellationToken cancellationToken)
        {
            var requestContent = Assert.IsType<StreamContent>(content);
            await requestContent.CopyToAsync(Stream.Null, cancellationToken);
            return CreateEmptyResponse();
        }
    }

    private sealed class ChunkedReadStream(byte[] source, int chunkSize) : Stream
    {
        private int position;

        public int ReadCount { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (position >= source.Length)
            {
                return 0;
            }

            await Task.Yield();

            var readLength = Math.Min(chunkSize, Math.Min(destination.Length, source.Length - position));
            source.AsMemory(position, readLength).CopyTo(destination);
            position += readLength;
            ReadCount++;
            return readLength;
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();
    }

    private sealed class CancelableBlockingStream : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();
    }
}
