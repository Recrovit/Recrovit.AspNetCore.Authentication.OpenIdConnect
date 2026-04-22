using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class OidcRemoteFailureEventTests
{
    [Fact]
    public async Task RemoteFailure_RedirectsHandledFailures()
    {
        using var serviceProvider = CreateServiceProvider(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Host:RemoteFailureRedirectPath"] = "/safe-landing"
        });
        var options = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);
        var context = CreateRemoteFailureContext(serviceProvider, new InvalidOperationException("access_denied"), "?error=access_denied");

        await options.Events!.RemoteFailure(context);

        Assert.Equal("/safe-landing", context.Response.Headers.Location.ToString());
        Assert.True(context.Result?.Handled ?? false);
    }

    [Fact]
    public async Task RemoteFailure_DoesNotHandleUnknownFailures()
    {
        using var serviceProvider = CreateServiceProvider();
        var options = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);
        var context = CreateRemoteFailureContext(serviceProvider, new InvalidOperationException("unexpected protocol failure"), "?error=server_error");

        await options.Events!.RemoteFailure(context);

        Assert.False(context.Result?.Handled ?? false);
        Assert.False(context.Response.Headers.ContainsKey("Location"));
    }

    private static ServiceProvider CreateServiceProvider(Dictionary<string, string?>? overrides = null)
    {
        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(TestConfiguration.Build(overrides), new FakeWebHostEnvironment());
        return services.BuildServiceProvider();
    }

    private static RemoteFailureContext CreateRemoteFailureContext(
        IServiceProvider serviceProvider,
        Exception exception,
        string queryString)
    {
        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };
        httpContext.Request.QueryString = new QueryString(queryString);

        var scheme = new AuthenticationScheme(
            OpenIdConnectDefaults.AuthenticationScheme,
            OpenIdConnectDefaults.AuthenticationScheme,
            typeof(PassThroughAuthenticationHandler));
        var options = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        return new RemoteFailureContext(httpContext, scheme, options, exception);
    }
}
