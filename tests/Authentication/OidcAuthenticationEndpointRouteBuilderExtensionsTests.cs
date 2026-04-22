using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class OidcAuthenticationEndpointRouteBuilderExtensionsTests
{
    [Fact]
    public async Task MapOidcAuthenticationEndpoints_UsesConfiguredEndpointBasePath()
    {
        await using var app = await CreateApplicationAsync("/oidc");
        using var client = app.GetTestClient();

        using var mappedResponse = await client.GetAsync("/oidc/logout", TestContext.Current.CancellationToken);
        using var unmappedResponse = await client.GetAsync("/authentication/logout", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, mappedResponse.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unmappedResponse.StatusCode);
    }

    [Fact]
    public async Task MapOidcAuthenticationEndpoints_MapsPrincipalEndpointAtConfiguredBasePath()
    {
        await using var app = await CreateApplicationAsync("/custom-auth", TestUsers.CreateAuthenticatedUser());
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/custom-auth/principal", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task<WebApplication> CreateApplicationAsync(string endpointBasePath, System.Security.Claims.ClaimsPrincipal? authenticatedUser = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(TestConfiguration.CreateBaseConfiguration(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Host:EndpointBasePath"] = endpointBasePath
        }));
        builder.AddRecrovitOpenIdConnectInfrastructure();
        builder.Services.Replace(ServiceDescriptor.Scoped<IDownstreamUserTokenStore>(_ => new InMemoryTokenStore(
            authenticatedUser ?? TestUsers.CreateAuthenticatedUser(),
            authenticatedUser is null
                ? null
                : new StoredOidcSessionTokenSet
                {
                    RefreshToken = "refresh-token",
                    ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
                })));
        builder.Services.Replace(ServiceDescriptor.Scoped<IDownstreamUserTokenProvider, StubDownstreamUserTokenProvider>());

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
}
