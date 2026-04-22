using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Configuration;

public sealed class SuppressAuthRedirectEndpointConventionBuilderExtensionsTests
{
    [Fact]
    public async Task DisableAuthRedirects_AddsMetadataToEndpoint()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        app.MapGet($"{OidcAuthenticationConstants.RequestPaths.ApiPrefix}/userinfo", () => "ok").DisableAuthRedirects();

        await app.StartAsync(TestContext.Current.CancellationToken);

        var endpoint = Assert.Single(app.Services.GetRequiredService<IEnumerable<EndpointDataSource>>()
            .SelectMany(static dataSource => dataSource.Endpoints));
        Assert.NotNull(endpoint.Metadata.GetMetadata<SuppressAuthRedirectMetadata>());
    }

    [Fact]
    public async Task DisableAuthRedirects_AddsMetadataToRouteGroupEndpoints()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        var group = app.MapGroup(OidcAuthenticationConstants.RequestPaths.ApiPrefix).DisableAuthRedirects();
        group.MapGet("/userinfo", () => "ok");

        await app.StartAsync(TestContext.Current.CancellationToken);

        var endpoint = Assert.Single(app.Services.GetRequiredService<IEnumerable<EndpointDataSource>>()
            .SelectMany(static dataSource => dataSource.Endpoints));
        Assert.NotNull(endpoint.Metadata.GetMetadata<SuppressAuthRedirectMetadata>());
    }
}
