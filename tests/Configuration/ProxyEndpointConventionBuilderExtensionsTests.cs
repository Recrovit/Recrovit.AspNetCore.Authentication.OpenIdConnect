using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Configuration;

public sealed class ProxyEndpointConventionBuilderExtensionsTests
{
    [Fact]
    public void StandardProxyMethods_ExposeExpectedValues()
    {
        Assert.Equal([HttpMethods.Get, HttpMethods.Post], ProxyEndpointConventionBuilderExtensions.StandardProxyMethods);
        Assert.Equal([HttpMethods.Get, HttpMethods.Post, HttpMethods.Delete], ProxyEndpointConventionBuilderExtensions.ProxyTransportMethods);
        Assert.Equal([HttpMethods.Get, HttpMethods.Post, HttpMethods.Put, HttpMethods.Patch, HttpMethods.Delete], ProxyEndpointConventionBuilderExtensions.DownstreamProxyMethods);
    }

    [Fact]
    public async Task AsProxyEndpoint_AddsProxyMetadataToEndpoint()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        app.MapGet("/proxy", () => "ok").AsProxyEndpoint();

        await app.StartAsync(TestContext.Current.CancellationToken);

        var endpoint = Assert.Single(app.Services.GetRequiredService<IEnumerable<EndpointDataSource>>()
            .SelectMany(static dataSource => dataSource.Endpoints));
        Assert.NotNull(endpoint.Metadata.GetMetadata<ProxyEndpointMetadata>());
    }

    [Fact]
    public async Task AsProxyEndpoint_AddsProxyMetadataToRouteGroupEndpoints()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();

        var group = app.MapGroup("/proxy").AsProxyEndpoint();
        group.MapGet("/items", () => "ok");

        await app.StartAsync(TestContext.Current.CancellationToken);

        var endpoint = Assert.Single(app.Services.GetRequiredService<IEnumerable<EndpointDataSource>>()
            .SelectMany(static dataSource => dataSource.Endpoints));
        Assert.NotNull(endpoint.Metadata.GetMetadata<ProxyEndpointMetadata>());
    }
}
