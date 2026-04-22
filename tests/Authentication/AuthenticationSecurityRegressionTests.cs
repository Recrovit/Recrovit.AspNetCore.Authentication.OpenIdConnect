using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Globalization;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class AuthenticationSecurityRegressionTests
{
    [Theory]
    [InlineData("/weather", "/weather")]
    [InlineData("https://evil.example", "/")]
    [InlineData("//evil.example", "/")]
    [InlineData(null, "/")]
    public async Task LoginEndpoint_UsesSanitizedReturnUrl(string? returnUrl, string expectedRedirectUri)
    {
        await using var app = await CreateLoginApplicationAsync();
        using var client = app.GetTestClient();

        var requestUri = returnUrl is null
            ? "/authentication/login"
            : $"/authentication/login?returnUrl={Uri.EscapeDataString(returnUrl)}";

        using var response = await client.GetAsync(requestUri, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(expectedRedirectUri, app.Services.GetRequiredService<ChallengeRecorder>().RedirectUri);
    }

    [Fact]
    public async Task LoginEndpoint_StoresDomainHintInChallengeProperties()
    {
        await using var app = await CreateLoginApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync(
            "/authentication/login?returnUrl=%2Fweather&domain_hint=contoso.com",
            TestContext.Current.CancellationToken);

        var recorder = app.Services.GetRequiredService<ChallengeRecorder>();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("/weather", recorder.RedirectUri);
        Assert.Equal("contoso.com", recorder.Items[AuthenticationEndpoints.DomainHintParameterName]);
    }

    [Theory]
    [InlineData("/authentication/login")]
    [InlineData("/authentication/login?domain_hint=")]
    [InlineData("/authentication/login?domain_hint=%20%20")]
    public async Task LoginEndpoint_DoesNotStoreEmptyDomainHint(string requestUri)
    {
        await using var app = await CreateLoginApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync(requestUri, TestContext.Current.CancellationToken);

        var recorder = app.Services.GetRequiredService<ChallengeRecorder>();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(recorder.Items.ContainsKey(AuthenticationEndpoints.DomainHintParameterName));
    }

    [Fact]
    public async Task LogoutEndpoint_ReturnsMethodNotAllowed_ForGetRequests()
    {
        await using var app = await CreateAuthenticatedLogoutApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/authentication/logout", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    [Fact]
    public async Task LogoutEndpoint_RejectsPostWithoutAntiforgeryToken()
    {
        await using var app = await CreateAuthenticatedLogoutApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.PostAsync(
            "/authentication/logout",
            new FormUrlEncodedContent([]),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task LogoutEndpoint_ReturnsBadRequest_WhenAntiforgeryFeatureAlreadyMarkedInvalid()
    {
        await using var app = await CreateAuthenticatedLogoutApplicationAsync(markAntiforgeryFeatureInvalid: true);
        using var client = app.GetTestClient();

        var tokens = await GetAntiforgeryTokensAsync(client);
        using var request = CreateLogoutRequest("/signed-out", tokens);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(app.Services.GetRequiredService<InMemoryTokenStore>().RemoveCalled);
        Assert.Empty(app.Services.GetRequiredService<SignOutRecorder>().Calls);
    }

    [Fact]
    public async Task LogoutEndpoint_RemovesTokensAndSignsOutUsingSanitizedReturnUrl()
    {
        await using var app = await CreateAuthenticatedLogoutApplicationAsync();
        using var client = app.GetTestClient();

        var tokens = await GetAntiforgeryTokensAsync(client);
        using var request = CreateLogoutRequest("https://evil.example", tokens);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(app.Services.GetRequiredService<InMemoryTokenStore>().RemoveCalled);

        var signOutCalls = app.Services.GetRequiredService<SignOutRecorder>().Calls;
        Assert.Equal(2, signOutCalls.Count);
        Assert.All(signOutCalls, call => Assert.Equal("/", call.RedirectUri));
        Assert.Equal(
            [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme],
            signOutCalls.Select(static call => call.Scheme).ToArray());
    }

    [Fact]
    public async Task SessionEndpoint_ReturnsReauthenticationResponse_WhenTokenRefreshRequiresSignIn()
    {
        await using var app = await CreateSessionApplicationAsync(
            new ThrowingDownstreamUserTokenProvider(new OidcReauthenticationRequiredException("reauth required")),
            TestUsers.CreateAuthenticatedUser(),
            sessionValidationDownstreamApiName: "SessionValidationApi");
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/authentication/session", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(
            OidcAuthenticationConstants.ResponseHeaders.ReauthenticationRequiredValue,
            response.Headers.GetValues(OidcAuthenticationConstants.ResponseHeaders.ReauthenticationRequired).Single());
    }

    [Fact]
    public async Task SessionEndpoint_ReturnsServiceUnavailable_WhenTokenRefreshFailsServerSide()
    {
        await using var app = await CreateSessionApplicationAsync(
            new ThrowingDownstreamUserTokenProvider(new OidcTokenRefreshFailedException("token endpoint unavailable")),
            TestUsers.CreateAuthenticatedUser(),
            sessionValidationDownstreamApiName: "SessionValidationApi");
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/authentication/session", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.False(response.Headers.Contains(OidcAuthenticationConstants.ResponseHeaders.ReauthenticationRequired));
    }

    [Fact]
    public async Task SessionEndpoint_ReturnsReauthenticationResponse_WhenAbsoluteTimeoutExpired()
    {
        var now = DateTimeOffset.Parse("2026-04-22T12:00:00Z", CultureInfo.InvariantCulture);
        var user = CreateUserWithAbsoluteExpiry(now.AddMinutes(-1));

        await using var app = await CreateCookieBackedSessionApplicationAsync(now, user);
        using var client = app.GetTestClient();
        var cookieHeader = await SignInAndGetCookieHeaderAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/authentication/session");
        request.Headers.Add("Cookie", cookieHeader);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(
            OidcAuthenticationConstants.ResponseHeaders.ReauthenticationRequiredValue,
            response.Headers.GetValues(OidcAuthenticationConstants.ResponseHeaders.ReauthenticationRequired).Single());
        Assert.True(app.Services.GetRequiredService<InMemoryTokenStore>().RemoveCalled);
    }

    [Fact]
    public async Task SessionEndpoint_Succeeds_WhenAbsoluteTimeoutStillValid()
    {
        var now = DateTimeOffset.Parse("2026-04-22T12:00:00Z", CultureInfo.InvariantCulture);
        var user = CreateUserWithAbsoluteExpiry(now.AddMinutes(30));

        await using var app = await CreateCookieBackedSessionApplicationAsync(now, user);
        using var client = app.GetTestClient();
        var cookieHeader = await SignInAndGetCookieHeaderAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/authentication/session");
        request.Headers.Add("Cookie", cookieHeader);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.False(app.Services.GetRequiredService<InMemoryTokenStore>().RemoveCalled);
    }

    [Fact]
    public async Task ProtectedEndpoint_ClearsSessionAndReturnsReauthenticationResponse_WhenAbsoluteTimeoutExpired()
    {
        var now = DateTimeOffset.Parse("2026-04-22T12:00:00Z", CultureInfo.InvariantCulture);
        var user = CreateUserWithAbsoluteExpiry(now.AddMinutes(-1));

        await using var app = await CreateCookieBackedSessionApplicationAsync(now, user);
        using var client = app.GetTestClient();
        var cookieHeader = await SignInAndGetCookieHeaderAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.Add("Cookie", cookieHeader);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(
            OidcAuthenticationConstants.ResponseHeaders.ReauthenticationRequiredValue,
            response.Headers.GetValues(OidcAuthenticationConstants.ResponseHeaders.ReauthenticationRequired).Single());
        Assert.True(app.Services.GetRequiredService<InMemoryTokenStore>().RemoveCalled);
    }

    private static async Task<WebApplication> CreateLoginApplicationAsync()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(TestConfiguration.CreateBaseConfiguration());
        builder.AddRecrovitOpenIdConnectInfrastructure();
        builder.Services.AddSingleton<ChallengeRecorder>();
        builder.Services.AddSingleton<SignOutRecorder>();
        builder.Services.Replace(ServiceDescriptor.Singleton<IAuthenticationService, RecordingAuthenticationService>());

        var app = builder.Build();
        app.UseRecrovitOpenIdConnectAuthentication();
        app.MapOidcAuthenticationEndpoints();

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<WebApplication> CreateAuthenticatedLogoutApplicationAsync(bool markAntiforgeryFeatureInvalid = false)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(TestConfiguration.CreateBaseConfiguration());
        builder.AddRecrovitOpenIdConnectInfrastructure();
        builder.Services.AddSingleton<InMemoryTokenStore>(_ => new InMemoryTokenStore(
            TestUsers.CreateAuthenticatedUser(),
            CreateStoredTokenEntry(TestUsers.CreateAuthenticatedUser())));
        builder.Services.AddSingleton<ChallengeRecorder>();
        builder.Services.AddSingleton<SignOutRecorder>();
        builder.Services.Replace(ServiceDescriptor.Singleton<IAuthenticationService, RecordingAuthenticationService>());
        builder.Services.AddScoped<IDownstreamUserTokenStore>(services => services.GetRequiredService<InMemoryTokenStore>());
        builder.Services.AddScoped<IDownstreamUserTokenProvider, StubDownstreamUserTokenProvider>();

        var app = builder.Build();
        app.Use((httpContext, next) =>
        {
            httpContext.User = TestUsers.CreateAuthenticatedUser();
            return next(httpContext);
        });
        app.UseRecrovitOpenIdConnectAuthentication();
        if (markAntiforgeryFeatureInvalid)
        {
            app.Use((httpContext, next) =>
            {
                if (httpContext.Request.Path == "/authentication/logout")
                {
                    httpContext.Features.Set<IAntiforgeryValidationFeature>(new StubAntiforgeryValidationFeature(isValid: false));
                }

                return next(httpContext);
            });
        }
        app.MapGet("/__test/antiforgery", (HttpContext httpContext, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(httpContext);
            return Results.Json(new AntiforgeryTokenResponse(tokens.RequestToken!, tokens.FormFieldName, tokens.HeaderName));
        });
        app.MapOidcAuthenticationEndpoints();

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<WebApplication> CreateSessionApplicationAsync(
        IDownstreamUserTokenProvider tokenProvider,
        ClaimsPrincipal? authenticatedUser,
        string? sessionValidationDownstreamApiName = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(TestConfiguration.CreateBaseConfiguration(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Host:SessionValidationDownstreamApiName"] = sessionValidationDownstreamApiName,
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:BaseUrl"] = "https://api.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:Scopes:0"] = "openid"
        }));
        builder.AddRecrovitOpenIdConnectInfrastructure();
        builder.Services.Replace(ServiceDescriptor.Scoped<IDownstreamUserTokenStore>(_ => new InMemoryTokenStore(
            authenticatedUser ?? TestUsers.CreateAuthenticatedUser(),
            CreateStoredTokenEntry(authenticatedUser))));
        builder.Services.Replace(ServiceDescriptor.Singleton<IDownstreamUserTokenProvider>(tokenProvider));

        var app = builder.Build();
        if (authenticatedUser is not null)
        {
            app.Use((httpContext, next) =>
            {
                httpContext.User = authenticatedUser;
                return next(httpContext);
            });
        }

        app.UseRecrovitOpenIdConnectAuthentication();
        app.MapOidcAuthenticationEndpoints();

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<WebApplication> CreateCookieBackedSessionApplicationAsync(DateTimeOffset now, ClaimsPrincipal authenticatedUser)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(TestConfiguration.CreateBaseConfiguration());
        builder.AddRecrovitOpenIdConnectInfrastructure();
        var tokenStore = new InMemoryTokenStore(authenticatedUser, CreateStoredTokenEntry(authenticatedUser));
        builder.Services.Replace(ServiceDescriptor.Singleton<TimeProvider>(new FixedTimeProvider(now)));
        builder.Services.AddSingleton(tokenStore);
        builder.Services.Replace(ServiceDescriptor.Scoped<IDownstreamUserTokenStore>(_ => tokenStore));
        builder.Services.Replace(ServiceDescriptor.Singleton<IDownstreamUserTokenProvider, StubDownstreamUserTokenProvider>());

        var app = builder.Build();
        app.UseRecrovitOpenIdConnectAuthentication();
        app.MapGet("/__test/sign-in", async (HttpContext httpContext) =>
        {
            await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, authenticatedUser);
            httpContext.Response.StatusCode = StatusCodes.Status204NoContent;
        });
        app.MapGet("/protected", () => Results.Ok()).RequireAuthorization();
        app.MapOidcAuthenticationEndpoints();

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<AntiforgeryTokenResponse> GetAntiforgeryTokensAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/__test/antiforgery", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var tokens = await response.Content.ReadFromJsonAsync<AntiforgeryTokenResponse>(cancellationToken: TestContext.Current.CancellationToken);
        var cookieHeader = response.Headers.GetValues("Set-Cookie").Single(static header => header.Contains(".AspNetCore.Antiforgery", StringComparison.Ordinal));
        return tokens! with { CookieHeader = cookieHeader.Split(';', 2)[0] };
    }

    private static HttpRequestMessage CreateLogoutRequest(string returnUrl, AntiforgeryTokenResponse tokens)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, $"/authentication/logout?returnUrl={Uri.EscapeDataString(returnUrl)}");
        request.Headers.Add("Cookie", tokens.CookieHeader);

        var formFieldName = string.IsNullOrWhiteSpace(tokens.FormFieldName)
            ? "__RequestVerificationToken"
            : tokens.FormFieldName;
        request.Content = new FormUrlEncodedContent([new KeyValuePair<string, string>(formFieldName, tokens.RequestToken)]);

        if (!string.IsNullOrWhiteSpace(tokens.HeaderName))
        {
            request.Headers.Add(tokens.HeaderName, tokens.RequestToken);
        }

        return request;
    }

    private static async Task<string> SignInAndGetCookieHeaderAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/__test/sign-in", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var cookieHeader = response.Headers.GetValues("Set-Cookie")
            .Single(static header => header.StartsWith(".AspNetCore.Cookies=", StringComparison.Ordinal)
                || header.StartsWith("__Host-Test=", StringComparison.Ordinal));
        return cookieHeader.Split(';', 2)[0];
    }

    private static StoredOidcSessionTokenSet? CreateStoredTokenEntry(ClaimsPrincipal? authenticatedUser)
    {
        var subjectId = authenticatedUser?.FindFirst("sub")?.Value
            ?? authenticatedUser?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        return string.IsNullOrWhiteSpace(subjectId)
            ? null
            : new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
            };
    }

    private static ClaimsPrincipal CreateUserWithAbsoluteExpiry(DateTimeOffset absoluteExpiresAtUtc)
    {
        var principal = TestUsers.CreateAuthenticatedUser();
        var identity = (ClaimsIdentity)principal.Identity!;
        identity.AddClaim(new Claim(
            OidcAuthenticationConstants.ProviderClaimNames.SessionIssuedAtUtc,
            absoluteExpiresAtUtc.AddHours(-1).ToString("O", CultureInfo.InvariantCulture)));
        identity.AddClaim(new Claim(
            OidcAuthenticationConstants.ProviderClaimNames.SessionAbsoluteExpiresAtUtc,
            absoluteExpiresAtUtc.ToString("O", CultureInfo.InvariantCulture)));
        return principal;
    }

    private sealed record AntiforgeryTokenResponse(string RequestToken, string? FormFieldName, string? HeaderName)
    {
        public string CookieHeader { get; init; } = string.Empty;
    }
}
