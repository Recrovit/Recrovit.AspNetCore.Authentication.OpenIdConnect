using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Proxy;

public sealed class DownstreamHttpProxyClientTests
{
    [Fact]
    public async Task SendAsync_AddsBearerToken_ForAuthenticatedUser()
    {
        var captureHandler = new CaptureRequestHandler();
        using var httpClient = new HttpClient(captureHandler);
        var client = TestFactories.CreateHttpProxyClient(httpClient, new StubDownstreamUserTokenProvider());

        using var response = await client.SendAsync(
            "SessionValidationApi",
            HttpMethod.Get,
            "/session/check?id=5",
            TestUsers.CreateAuthenticatedUser(),
            content: null,
            headers: [],
            CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Bearer", captureHandler.LastRequest!.Headers.Authorization!.Scheme);
        Assert.Equal("access-token", captureHandler.LastRequest.Headers.Authorization.Parameter);
        Assert.Equal("https://api.example.com/gateway/session/check?id=5", captureHandler.LastRequest.RequestUri!.ToString());
    }

    [Fact]
    public async Task SendAsync_SkipsBearerToken_ForAnonymousUser()
    {
        var captureHandler = new CaptureRequestHandler();
        using var httpClient = new HttpClient(captureHandler);
        var client = TestFactories.CreateHttpProxyClient(httpClient, new StubDownstreamUserTokenProvider());

        using var response = await client.SendAsync(
            "SessionValidationApi",
            HttpMethod.Post,
            "/session/check",
            user: null,
            content: new StringContent("hello"),
            headers:
            [
                new KeyValuePair<string, StringValues>("Accept-Language", "hu-HU"),
                new KeyValuePair<string, StringValues>("Cookie", "blocked=true")
            ],
            CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(captureHandler.LastRequest!.Headers.Authorization);
        Assert.True(captureHandler.LastRequest.Headers.Contains("Accept-Language"));
        Assert.False(captureHandler.LastRequest.Headers.Contains("Cookie"));
    }

    [Fact]
    public async Task SendAsync_ForwardsOnlyAllowlistedHeaders()
    {
        var captureHandler = new CaptureRequestHandler();
        using var httpClient = new HttpClient(captureHandler);
        var client = TestFactories.CreateHttpProxyClient(httpClient, new StubDownstreamUserTokenProvider());

        using var response = await client.SendAsync(
            "SessionValidationApi",
            HttpMethod.Get,
            "/session/check?culture=hu",
            user: null,
            content: null,
            headers:
            [
                new KeyValuePair<string, StringValues>("Accept", OidcAuthenticationConstants.MediaTypes.Json),
                new KeyValuePair<string, StringValues>("ACCEPT-LANGUAGE", "hu-HU"),
                new KeyValuePair<string, StringValues>("If-None-Match", "\"etag-1\""),
                new KeyValuePair<string, StringValues>("RgF-Trace-Id", "trace-123"),
                new KeyValuePair<string, StringValues>("Host", "malicious.example"),
                new KeyValuePair<string, StringValues>("Cookie", "blocked=true"),
                new KeyValuePair<string, StringValues>("Authorization", "Bearer should-not-forward"),
                new KeyValuePair<string, StringValues>("Connection", "keep-alive"),
                new KeyValuePair<string, StringValues>("X-Forwarded-For", "10.0.0.1")
            ],
            CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var request = captureHandler.LastRequest!;
        var forwardedInputHeaders = request.Headers.Select(header => header.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.True(request.Headers.Contains("Accept"));
        Assert.True(request.Headers.Contains("Accept-Language"));
        Assert.True(request.Headers.Contains("If-None-Match"));
        Assert.True(request.Headers.Contains("RgF-Trace-Id"));

        Assert.Null(request.Headers.Authorization);
        Assert.False(request.Headers.Contains("Cookie"));
        Assert.False(request.Headers.Contains("Connection"));
        Assert.False(request.Headers.Contains("X-Forwarded-For"));
        Assert.Null(request.Headers.Host);

        Assert.Equal(
            ["Accept", "Accept-Language", "If-None-Match", "RgF-Trace-Id"],
            forwardedInputHeaders.OrderBy(static header => header, StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task SendAsync_LogsMaskedDownstreamUri_WithoutRawQueryValues()
    {
        var captureHandler = new CaptureRequestHandler();
        using var httpClient = new HttpClient(captureHandler);
        var logger = new ListLogger<Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy.DownstreamHttpProxyClient>();
        var client = TestFactories.CreateHttpProxyClient(httpClient, new StubDownstreamUserTokenProvider(), logger);

        using var response = await client.SendAsync(
            "SessionValidationApi",
            HttpMethod.Get,
            "/session/check?code=secret-code&state=opaque-state",
            TestUsers.CreateAuthenticatedUser(),
            content: null,
            headers: [],
            CancellationToken.None);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var infoMessages = logger.Entries
            .Where(static entry => entry.Level == LogLevel.Information)
            .Select(static entry => entry.Message)
            .ToArray();

        Assert.Contains(infoMessages, static message => message.Contains("/gateway/session/check?code=***&state=***", StringComparison.Ordinal));
        Assert.DoesNotContain(infoMessages, static message => message.Contains("secret-code", StringComparison.Ordinal));
        Assert.DoesNotContain(infoMessages, static message => message.Contains("opaque-state", StringComparison.Ordinal));
    }

    [Fact]
    public async Task SendAsync_LogsError_WhenDownstreamTransportFails()
    {
        using var httpClient = new HttpClient(new ThrowingHttpMessageHandler(new HttpRequestException("boom")));
        var logger = new ListLogger<Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy.DownstreamHttpProxyClient>();
        var client = TestFactories.CreateHttpProxyClient(httpClient, new StubDownstreamUserTokenProvider(), logger);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.SendAsync(
            "SessionValidationApi",
            HttpMethod.Get,
            "/session/check?code=secret-code",
            TestUsers.CreateAuthenticatedUser(),
            content: null,
            headers: [],
            CancellationToken.None));

        var error = Assert.Single(logger.Entries, static entry => entry.Level == LogLevel.Error);
        Assert.Contains("failed", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret-code", error.Message, StringComparison.Ordinal);
    }
}
