using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Proxy;

public sealed class DownstreamProxyRequestBodyIntegrationTests
{
    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_ForwardsChunkedPostBodyWithoutIncomingContentLength()
    {
        const string payload = """{"message":"chunked-body"}""";

        await using var downstreamServer = await LoopbackHttpServer.StartAsync((_, _) => Task.FromResult(new LoopbackHttpResponse(HttpStatusCode.Accepted)));
        await using var proxyHost = await ProxyHost.StartAsync(
            downstreamServer.BaseAddress,
            HttpProtocols.Http1AndHttp2);
        using var client = proxyHost.CreateClient();
        using var request = CreateProxyRequest(HttpMethod.Post, proxyHost.BaseAddress, "/downstream/GraphApi/ingest?trace=1", HttpVersion.Version11);

        request.Content = new StreamContent(new UploadStream(Encoding.ASCII.GetBytes(payload), 5));
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        request.Content.Headers.ContentEncoding.Add("gzip");
        request.Content.Headers.ContentLanguage.Add("hu");

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal(HttpVersion.Version11, response.Version);

        Assert.True(downstreamServer.Requests.TryDequeue(out var downstreamRequest));
        Assert.Equal("POST", downstreamRequest.Method);
        Assert.Equal("/ingest?trace=1", downstreamRequest.Path);
        Assert.Equal(payload, downstreamRequest.Body);
        Assert.Equal("application/json", downstreamRequest.Headers["Content-Type"]);
        Assert.Equal("gzip", downstreamRequest.Headers["Content-Encoding"]);
        Assert.Equal("hu", downstreamRequest.Headers["Content-Language"]);
        Assert.False(downstreamRequest.Headers.ContainsKey("Content-Length"));
        Assert.Equal("chunked", downstreamRequest.Headers["Transfer-Encoding"]);
    }

    [Fact]
    public async Task MapDownstreamApiProxyEndpoints_ForwardsHttp2PostBody()
    {
        const string payload = """{"message":"http2-body"}""";

        await using var downstreamServer = await LoopbackHttpServer.StartAsync((_, _) => Task.FromResult(new LoopbackHttpResponse(HttpStatusCode.OK)));
        await using var proxyHost = await ProxyHost.StartAsync(
            downstreamServer.BaseAddress,
            HttpProtocols.Http1AndHttp2);
        using var client = proxyHost.CreateClient();
        using var request = CreateProxyRequest(HttpMethod.Post, proxyHost.BaseAddress, "/downstream/GraphApi/ingest", HttpVersion.Version20);

        request.Content = new StreamContent(new UploadStream(Encoding.ASCII.GetBytes(payload), 4));
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(HttpVersion.Version20, response.Version);

        Assert.True(downstreamServer.Requests.TryDequeue(out var downstreamRequest));
        Assert.Equal("POST", downstreamRequest.Method);
        Assert.Equal("/ingest", downstreamRequest.Path);
        Assert.Equal(payload, downstreamRequest.Body);
        Assert.Equal("application/json", downstreamRequest.Headers["Content-Type"]);
    }

    private static HttpRequestMessage CreateProxyRequest(HttpMethod method, Uri baseAddress, string relativePath, Version version)
    {
        var request = new HttpRequestMessage(method, new Uri(baseAddress, relativePath))
        {
            Version = version,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact
        };
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "same-origin");
        request.Headers.TryAddWithoutValidation("Origin", baseAddress.GetLeftPart(UriPartial.Authority));
        return request;
    }

    private sealed class ProxyHost : IAsyncDisposable
    {
        private readonly TemporaryPfxCertificate certificate;
        private readonly HttpClient downstreamClient;

        private ProxyHost(WebApplication app, HttpClient downstreamClient, TemporaryPfxCertificate certificate)
        {
            App = app;
            this.downstreamClient = downstreamClient;
            this.certificate = certificate;
        }

        public WebApplication App { get; }

        public Uri BaseAddress { get; private set; } = null!;

        public static async Task<ProxyHost> StartAsync(Uri downstreamBaseAddress, HttpProtocols protocols)
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = Environments.Development
            });
            var certificate = CreateTemporaryServerCertificate();

            builder.WebHost.ConfigureKestrel(options =>
            {
                options.Listen(IPAddress.Loopback, 0, listenOptions =>
                {
                    listenOptions.Protocols = protocols;
                    listenOptions.UseHttps(certificate.Path, certificate.Password);
                });
            });

            builder.Services.AddAuthorization();
            builder.Services.AddAntiforgery();
            builder.Services.Replace(ServiceDescriptor.Singleton<IAntiforgery>(new StubAntiforgery(isRequestValid: true)));

            var downstreamApiCatalog = new DownstreamApiCatalog(new Dictionary<string, DownstreamApiDefinition>(StringComparer.OrdinalIgnoreCase)
            {
                ["GraphApi"] = new()
                {
                    BaseUrl = downstreamBaseAddress.ToString(),
                    RelativePath = string.Empty,
                    Scopes = ["graph.read"]
                }
            });

            builder.Services.AddSingleton(downstreamApiCatalog);
            builder.Services.AddSingleton<IOptions<OidcAuthenticationOptions>>(Options.Create(new OidcAuthenticationOptions
            {
                DownstreamProxyRequestProtection = new DownstreamProxyRequestProtectionOptions()
            }));

            var proxyAssembly = typeof(IDownstreamHttpProxyClient).Assembly;
            var evaluatorInterface = proxyAssembly.GetType("Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy.IDownstreamProxyRequestProtectionEvaluator")
                ?? throw new InvalidOperationException("The downstream proxy request protection evaluator interface could not be found.");
            var evaluatorType = proxyAssembly.GetType("Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy.DownstreamProxyRequestProtectionEvaluator")
                ?? throw new InvalidOperationException("The downstream proxy request protection evaluator type could not be found.");
            builder.Services.AddSingleton(evaluatorInterface, evaluatorType);

            var downstreamClient = new HttpClient();
            var proxyClient = TestFactories.CreateHttpProxyClient(
                downstreamClient,
                new StubDownstreamUserTokenProvider(),
                NullLogger<DownstreamHttpProxyClient>.Instance,
                downstreamApiCatalog);
            builder.Services.Replace(ServiceDescriptor.Singleton<IDownstreamHttpProxyClient>(proxyClient));
            builder.Services.Replace(ServiceDescriptor.Singleton<IDownstreamTransportProxyClient>(new NoOpDownstreamTransportProxyClient()));

            var app = builder.Build();
            app.Use((context, next) =>
            {
                context.User = TestUsers.CreateAuthenticatedUser();
                return next(context);
            });
            app.Use(async (context, next) =>
            {
                context.Features.Set<IAntiforgeryValidationFeature>(new StubAntiforgeryValidationFeature(isValid: true));
                await next(context);
            });
            app.UseAuthorization();
            app.UseAntiforgery();
            app.MapDownstreamApiProxyEndpoints();

            await app.StartAsync(TestContext.Current.CancellationToken);

            var host = new ProxyHost(app, downstreamClient, certificate)
            {
                BaseAddress = new Uri(app.Urls.Single(), UriKind.Absolute)
            };

            return host;
        }

        public HttpClient CreateClient()
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = static (_, _, _, _) => true
            };

            return new HttpClient(handler)
            {
                BaseAddress = BaseAddress
            };
        }

        public async ValueTask DisposeAsync()
        {
            downstreamClient.Dispose();
            await App.DisposeAsync();
            certificate.Dispose();
        }
    }

    private sealed class NoOpDownstreamTransportProxyClient : IDownstreamTransportProxyClient
    {
        public Task ProxyWebSocketAsync(HttpContext context, string downstreamApiName, string pathAndQuery, ClaimsPrincipal? user, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    private sealed class UploadStream(byte[] source, int chunkSize) : Stream
    {
        private int position;

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
            cancellationToken.ThrowIfCancellationRequested();
            if (position >= source.Length)
            {
                return 0;
            }

            await Task.Yield();

            var readLength = Math.Min(chunkSize, Math.Min(buffer.Length, source.Length - position));
            source.AsMemory(position, readLength).CopyTo(buffer);
            position += readLength;
            return readLength;
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();
    }

    private static TemporaryPfxCertificate CreateTemporaryServerCertificate()
    {
        const string password = "test-password";
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=localhost",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1")],
            critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(sanBuilder.Build());

        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var tempPath = Path.Combine(Path.GetTempPath(), $"recrovit-proxy-{Guid.NewGuid():n}.pfx");
        File.WriteAllBytes(tempPath, certificate.Export(X509ContentType.Pkcs12, password));
        var loadedCertificate = X509CertificateLoader.LoadPkcs12FromFile(
            tempPath,
            password,
            X509KeyStorageFlags.DefaultKeySet);
        return new TemporaryPfxCertificate(tempPath, password, loadedCertificate);
    }
}
