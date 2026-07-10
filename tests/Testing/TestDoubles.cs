using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;

internal sealed class InMemoryTokenStore : IDownstreamUserTokenStore
{
    private readonly Dictionary<string, StoredOidcSessionTokenSet> sessionTokenSets = new(StringComparer.Ordinal);
    private readonly Dictionary<string, CachedDownstreamApiTokenEntry> apiTokens = new(StringComparer.Ordinal);

    public StoredOidcSessionTokenSet? StoredSessionTokenSet { get; private set; }

    public IReadOnlyDictionary<string, CachedDownstreamApiTokenEntry> ApiTokens => apiTokens;

    public bool RemoveCalled { get; private set; }

    public List<string> RemovedSessionKeys { get; } = [];

    public List<string> StoredSessionKeys { get; } = [];

    public InMemoryTokenStore(
        StoredOidcSessionTokenSet? initialSessionTokenSet = null,
        IReadOnlyDictionary<string, CachedDownstreamApiTokenEntry>? initialApiTokens = null)
        : this(TestUsers.CreateAuthenticatedUser(), initialSessionTokenSet, initialApiTokens)
    {
    }

    public InMemoryTokenStore(
        ClaimsPrincipal initialUser,
        StoredOidcSessionTokenSet? initialSessionTokenSet = null,
        IReadOnlyDictionary<string, CachedDownstreamApiTokenEntry>? initialApiTokens = null)
    {
        if (initialSessionTokenSet is not null)
        {
            sessionTokenSets[CreateSessionKey(initialUser)] = initialSessionTokenSet;
        }

        if (initialApiTokens is not null)
        {
            foreach (var entry in initialApiTokens)
            {
                apiTokens[$"{CreateSessionKey(initialUser)}|{entry.Key}"] = entry.Value;
            }
        }
    }

    public Task<StoredOidcSessionTokenSet?> GetSessionTokenSetAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        sessionTokenSets.TryGetValue(CreateSessionKey(user), out var tokenSet);
        return Task.FromResult(tokenSet);
    }

    public Task StoreSessionTokenSetAsync(ClaimsPrincipal user, StoredOidcSessionTokenSet tokenSet, CancellationToken cancellationToken)
    {
        StoredSessionTokenSet = tokenSet;
        var sessionKey = CreateSessionKey(user);
        StoredSessionKeys.Add(sessionKey);
        sessionTokenSets[sessionKey] = tokenSet;
        return Task.CompletedTask;
    }

    public Task<CachedDownstreamApiTokenEntry?> GetApiTokenAsync(
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> scopes,
        CancellationToken cancellationToken)
    {
        apiTokens.TryGetValue(CreateApiKey(user, downstreamApiName, scopes), out var entry);
        return Task.FromResult(entry);
    }

    public Task StoreApiTokenAsync(
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> scopes,
        CachedDownstreamApiTokenEntry tokenEntry,
        CancellationToken cancellationToken)
    {
        apiTokens[CreateApiKey(user, downstreamApiName, scopes)] = tokenEntry;
        return Task.CompletedTask;
    }

    public Task RemoveAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        RemoveCalled = true;
        var sessionKey = CreateSessionKey(user);
        RemovedSessionKeys.Add(sessionKey);
        sessionTokenSets.Remove(sessionKey);
        foreach (var apiKey in apiTokens.Keys.Where(key => key.StartsWith($"{sessionKey}|", StringComparison.Ordinal)).ToArray())
        {
            apiTokens.Remove(apiKey);
        }
        return Task.CompletedTask;
    }

    private static string CreateApiKey(ClaimsPrincipal user, string downstreamApiName, IReadOnlyCollection<string> scopes)
    {
        return $"{CreateSessionKey(user)}|{downstreamApiName}:{string.Join(" ", scopes.OrderBy(scope => scope, StringComparer.Ordinal))}";
    }

    private static string CreateSessionKey(ClaimsPrincipal user)
    {
        var subjectId = user.FindFirst("sub")?.Value
            ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? throw new InvalidOperationException("No unique subject identifier was found for the authenticated user.");
        var issuer = user.FindFirst("iss")?.Value
            ?? user.FindFirst("sub")?.Issuer
            ?? throw new InvalidOperationException("No issuer identifier was found for the authenticated user.");
        var sessionId = user.FindFirst(OidcAuthenticationConstants.ProviderClaimNames.LocalSessionId)?.Value
            ?? throw new InvalidOperationException("No local session identifier was found for the authenticated user.");
        return $"{issuer}:{subjectId}:{sessionId}";
    }
}

internal sealed class StubHttpClientFactory(string payload, HttpStatusCode statusCode = HttpStatusCode.OK) : IHttpClientFactory
{
    public HttpClient CreateClient(string name)
    {
        return new HttpClient(new StubHttpMessageHandler(payload, statusCode))
        {
            BaseAddress = new Uri("https://idp.example.com")
        };
    }
}

internal sealed class DelegatingHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
{
    public HttpClient CreateClient(string name)
    {
        return new HttpClient(handler)
        {
            BaseAddress = new Uri("https://idp.example.com")
        };
    }
}

internal sealed class StubDownstreamUserTokenProvider : IDownstreamUserTokenProvider
{
    public Task<string> GetAccessTokenAsync(ClaimsPrincipal user, string downstreamApiName, CancellationToken cancellationToken)
    {
        return Task.FromResult("access-token");
    }
}

internal sealed class FixedClientAssertionService(string assertion) : IOidcClientAssertionService
{
    public string CreateClientAssertion(string tokenEndpoint)
    {
        return assertion;
    }
}

internal sealed class ThrowingDownstreamUserTokenProvider(Exception exception) : IDownstreamUserTokenProvider
{
    public Task<string> GetAccessTokenAsync(ClaimsPrincipal user, string downstreamApiName, CancellationToken cancellationToken)
    {
        return Task.FromException<string>(exception);
    }
}

internal sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => utcNow;
}

internal sealed class RecordingDownstreamHttpProxyClient(HttpResponseMessage response) : IDownstreamHttpProxyClient
{
    public string? DownstreamApiName { get; private set; }

    public HttpMethod? Method { get; private set; }

    public string? PathAndQuery { get; private set; }

    public ClaimsPrincipal? User { get; private set; }

    public IReadOnlyList<KeyValuePair<string, StringValues>> Headers { get; private set; } = [];

    public string? ContentType { get; private set; }

    public string? ContentBody { get; private set; }

    public async Task<HttpResponseMessage> SendAsync(
        string downstreamApiName,
        HttpMethod method,
        string pathAndQuery,
        ClaimsPrincipal? user,
        HttpContent? content,
        IEnumerable<KeyValuePair<string, StringValues>> headers,
        CancellationToken cancellationToken)
    {
        DownstreamApiName = downstreamApiName;
        Method = method;
        PathAndQuery = pathAndQuery;
        User = user;
        Headers = headers.ToArray();
        ContentType = content?.Headers.ContentType?.ToString();
        ContentBody = content is null
            ? null
            : await content.ReadAsStringAsync(cancellationToken);
        return response;
    }
}

internal sealed class StubAntiforgery(bool isRequestValid) : IAntiforgery
{
    public AntiforgeryTokenSet GetAndStoreTokens(HttpContext httpContext)
    {
        return new AntiforgeryTokenSet("request-token", "cookie-token", "__RequestVerificationToken", "RequestVerificationToken");
    }

    public AntiforgeryTokenSet GetTokens(HttpContext httpContext)
    {
        return new AntiforgeryTokenSet("request-token", "cookie-token", "__RequestVerificationToken", "RequestVerificationToken");
    }

    public Task<bool> IsRequestValidAsync(HttpContext httpContext)
    {
        return Task.FromResult(isRequestValid);
    }

    public Task ValidateRequestAsync(HttpContext httpContext)
    {
        if (!isRequestValid)
        {
            throw new AntiforgeryValidationException("Invalid antiforgery token.");
        }

        return Task.CompletedTask;
    }

    public void SetCookieTokenAndHeader(HttpContext httpContext)
    {
    }
}

internal sealed class StubAntiforgeryValidationFeature(bool isValid, Exception? error = null) : IAntiforgeryValidationFeature
{
    public bool IsValid => isValid;

    public Exception? Error => error;
}

internal sealed class StubHttpMessageHandler(string payload, HttpStatusCode statusCode) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(payload)
        };

        return Task.FromResult(response);
    }
}

internal sealed class CoordinatedRefreshHandler(string payload) : HttpMessageHandler
{
    private readonly TaskCompletionSource firstRequestStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource releaseFirstResponse = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int requestCount;

    public int RequestCount => Volatile.Read(ref requestCount);

    public Task FirstRequestStarted => firstRequestStarted.Task;

    public void ReleaseFirstResponse() => releaseFirstResponse.TrySetResult();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var currentCount = Interlocked.Increment(ref requestCount);
        if (currentCount == 1)
        {
            firstRequestStarted.TrySetResult();
            await releaseFirstResponse.Task.WaitAsync(cancellationToken);
        }

        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(payload)
        };
    }
}

internal sealed class CaptureRequestHandler(
    string? payload = null,
    HttpStatusCode statusCode = HttpStatusCode.OK) : HttpMessageHandler
{
    private static readonly string DefaultPayload =
        $$"""{"access_token":"captured-token","{{OidcAuthenticationConstants.TokenNames.ExpiresIn}}":120}""";

    public HttpRequestMessage? LastRequest { get; private set; }

    public string? LastRequestContent { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        LastRequestContent = request.Content is null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);
        return new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(payload ?? DefaultPayload)
        };
    }
}

internal sealed class ThrowingHttpMessageHandler(Exception exception) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return Task.FromException<HttpResponseMessage>(exception);
    }
}

internal sealed class ChallengeRecorder
{
    public int ChallengeCount { get; private set; }

    public string? RedirectUri { get; private set; }

    public IReadOnlyDictionary<string, string?> Items { get; private set; } = new Dictionary<string, string?>();

    public void Record(AuthenticationProperties? properties)
    {
        ChallengeCount++;
        RedirectUri = properties?.RedirectUri;
        Items = properties?.Items.ToDictionary(static pair => pair.Key, static pair => (string?)pair.Value)
            ?? new Dictionary<string, string?>();
    }
}

internal sealed class SignOutRecorder
{
    public List<SignOutCall> Calls { get; } = [];

    public void Record(string scheme, AuthenticationProperties? properties)
    {
        Calls.Add(new SignOutCall(
            scheme,
            properties?.RedirectUri,
            properties?.Items.ToDictionary(static pair => pair.Key, static pair => (string?)pair.Value)
                ?? new Dictionary<string, string?>()));
    }

    internal sealed record SignOutCall(string Scheme, string? RedirectUri, IReadOnlyDictionary<string, string?> Items);
}

internal sealed class RecordingAuthenticationService(
    ChallengeRecorder challengeRecorder,
    SignOutRecorder signOutRecorder) : IAuthenticationService
{
    public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
    {
        return Task.FromResult(AuthenticateResult.NoResult());
    }

    public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
    {
        challengeRecorder.Record(properties);
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }

    public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }

    public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
    {
        return Task.CompletedTask;
    }

    public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
    {
        signOutRecorder.Record(scheme ?? string.Empty, properties);
        context.Response.StatusCode = StatusCodes.Status200OK;
        return Task.CompletedTask;
    }
}

internal sealed class RedirectingAuthenticationService : IAuthenticationService
{
    public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
    {
        return Task.FromResult(AuthenticateResult.NoResult());
    }

    public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
    {
        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = "/signin";
        return Task.CompletedTask;
    }

    public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }

    public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
    {
        return Task.CompletedTask;
    }

    public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
    {
        context.Response.StatusCode = StatusCodes.Status200OK;
        return Task.CompletedTask;
    }
}

internal sealed class RecordingChallengeHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        return Task.FromResult(AuthenticateResult.NoResult());
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Context.RequestServices.GetRequiredService<ChallengeRecorder>().Record(properties);
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}

internal sealed class PassThroughAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        return Task.FromResult(AuthenticateResult.NoResult());
    }
}

internal sealed class RecordingSignOutHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : SignOutAuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        return Task.FromResult(AuthenticateResult.NoResult());
    }

    protected override Task HandleSignOutAsync(AuthenticationProperties? properties)
    {
        Context.RequestServices.GetRequiredService<SignOutRecorder>().Record(Scheme.Name, properties);
        Response.StatusCode = StatusCodes.Status200OK;
        return Task.CompletedTask;
    }
}

internal sealed class StaticConfigurationManager(string tokenEndpoint) : Microsoft.IdentityModel.Protocols.IConfigurationManager<Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration>
{
    private readonly Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration configuration = new()
    {
        TokenEndpoint = tokenEndpoint
    };

    public Task<Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
    {
        return Task.FromResult(configuration);
    }

    public void RequestRefresh()
    {
    }
}

internal sealed class ThrowingConfigurationManager : Microsoft.IdentityModel.Protocols.IConfigurationManager<Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration>
{
    public Task<Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
    {
        throw new HttpRequestException("metadata unavailable");
    }

    public void RequestRefresh()
    {
    }
}

internal sealed class StaticOptionsMonitor<TOptions>(TOptions currentValue) : IOptionsMonitor<TOptions>
{
    public TOptions CurrentValue => currentValue;

    public TOptions Get(string? name) => currentValue;

    public IDisposable? OnChange(Action<TOptions, string?> listener) => null;
}

internal sealed class ThrowingAuthorizationHandler : IAuthorizationMiddlewareResultHandler
{
    public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        throw new InvalidOperationException("Fallback handler should not be called.");
    }
}

internal sealed class RecordingAuthorizationHandler : IAuthorizationMiddlewareResultHandler
{
    public bool WasCalled { get; private set; }

    public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        WasCalled = true;
        return Task.CompletedTask;
    }
}

internal sealed class FakeWebHostEnvironment : Microsoft.AspNetCore.Hosting.IWebHostEnvironment
{
    public string ApplicationName { get; set; } = "Tests";

    public IFileProvider WebRootFileProvider { get; set; } = null!;

    public string WebRootPath { get; set; } = string.Empty;

    public string EnvironmentName { get; set; } = Environments.Development;

    public string ContentRootPath { get; set; } = string.Empty;

    public IFileProvider ContentRootFileProvider { get; set; } = null!;
}

internal sealed class FakeHostEnvironment : IHostEnvironment
{
    public string EnvironmentName { get; set; } = Environments.Development;

    public string ApplicationName { get; set; } = "Tests";

    public string ContentRootPath { get; set; } = string.Empty;

    public IFileProvider ContentRootFileProvider { get; set; } = null!;
}

internal sealed class TemporaryPfxCertificate : IDisposable
{
    public TemporaryPfxCertificate(string path, string? password, X509Certificate2 certificate)
    {
        Path = path;
        Password = password;
        Certificate = certificate;
    }

    public string Path { get; }

    public string? Password { get; }

    public X509Certificate2 Certificate { get; }

    public void Dispose()
    {
        Certificate.Dispose();
        if (File.Exists(Path))
        {
            File.Delete(Path);
        }
    }
}

internal static class TestCertificates
{
    public static TemporaryPfxCertificate CreateTemporaryPfx(string? password = "test-password")
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Recrovit.Test.Client",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var tempPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"recrovit-oidc-{Guid.NewGuid():n}.pfx");
        File.WriteAllBytes(tempPath, certificate.Export(X509ContentType.Pkcs12, password));
        return new TemporaryPfxCertificate(tempPath, password, certificate);
    }

    public static TemporaryPfxCertificate CreateTemporaryEcdsaPfx(string? password = "test-password")
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            "CN=Recrovit.Test.Client",
            ecdsa,
            HashAlgorithmName.SHA256);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var tempPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"recrovit-oidc-{Guid.NewGuid():n}.pfx");
        File.WriteAllBytes(tempPath, certificate.Export(X509ContentType.Pkcs12, password));
        return new TemporaryPfxCertificate(tempPath, password, certificate);
    }
}

internal sealed class StubDistributedCache : IDistributedCache
{
    public byte[]? Get(string key) => null;

    public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
    {
        return Task.FromResult<byte[]?>(null);
    }

    public void Refresh(string key)
    {
    }

    public Task RefreshAsync(string key, CancellationToken token = default)
    {
        return Task.CompletedTask;
    }

    public void Remove(string key)
    {
    }

    public Task RemoveAsync(string key, CancellationToken token = default)
    {
        return Task.CompletedTask;
    }

    public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
    {
    }

    public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
    {
        return Task.CompletedTask;
    }
}

internal sealed class TestEndpointDataSource(params Endpoint[] endpoints) : EndpointDataSource
{
    private readonly IReadOnlyList<Endpoint> endpointList = endpoints;

    public override IReadOnlyList<Endpoint> Endpoints => endpointList;

    public override IChangeToken GetChangeToken()
    {
        return NullChangeToken.Singleton;
    }
}
