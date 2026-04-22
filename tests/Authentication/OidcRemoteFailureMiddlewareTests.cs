using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class OidcRemoteFailureMiddlewareTests
{
    [Theory]
    [InlineData("/signin-oidc?error=access_denied")]
    [InlineData("/signin-oidc?error=login_required")]
    public async Task Middleware_RedirectsHandledCallbackFailures(string requestUri)
    {
        await using var app = await CreateApplicationAsync();
        using var client = app.GetTestClient();
        client.DefaultRequestHeaders.Add("Cookie", "oidc-nonce.cookie=1; oidc-correlation.cookie=1");

        using var response = await client.GetAsync(requestUri, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/safe-landing", response.Headers.Location?.OriginalString);
        Assert.True(response.Headers.TryGetValues("Set-Cookie", out var setCookieHeaders));
        Assert.Contains(setCookieHeaders, value => value.Contains("oidc-nonce.cookie=", StringComparison.Ordinal));
        Assert.Contains(setCookieHeaders, value => value.Contains("oidc-correlation.cookie=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Middleware_DoesNotInterceptRequestsOutsideCallbackPath()
    {
        await using var app = await CreateApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/other?error=access_denied", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("next", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Middleware_DoesNotInterceptUnknownCallbackErrors()
    {
        await using var app = await CreateApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/signin-oidc?error=server_error", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("next", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Middleware_RedirectsHandledCallbackFailures_FromPostedFormData()
    {
        await using var app = await CreateApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.PostAsync(
            "/signin-oidc",
            new FormUrlEncodedContent(
            [
                new KeyValuePair<string, string>(OidcAuthenticationConstants.TokenNames.Error, "access_denied"),
                new KeyValuePair<string, string>("error_description", "user cancelled")
            ]),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/safe-landing", response.Headers.Location?.OriginalString);
    }

    private static async Task<WebApplication> CreateApplicationAsync()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, PassThroughAuthenticationHandler>(
                OpenIdConnectDefaults.AuthenticationScheme,
                static _ => { });
        builder.Services.AddAuthorization();
        builder.Services.AddAntiforgery();
        builder.Services.AddSingleton<IOptions<OidcAuthenticationOptions>>(Options.Create(new OidcAuthenticationOptions
        {
            RemoteFailureRedirectPath = "/safe-landing"
        }));
        builder.Services.AddSingleton<IOptions<ActiveOidcProviderOptions>>(Options.Create(new ActiveOidcProviderOptions
        {
            ProviderName = "TestProvider"
        }));
        builder.Services.AddSingleton<IOptionsMonitor<OpenIdConnectOptions>>(new StaticOptionsMonitor<OpenIdConnectOptions>(CreateOpenIdOptions()));

        var app = builder.Build();
        app.UseRecrovitOpenIdConnectAuthentication();
        app.MapGet("/{**path}", () => "next");

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static OpenIdConnectOptions CreateOpenIdOptions()
    {
        var options = new OpenIdConnectOptions
        {
            CallbackPath = "/signin-oidc"
        };
        options.NonceCookie.Name = "oidc-nonce.";
        options.CorrelationCookie.Name = "oidc-correlation.";
        return options;
    }
}
