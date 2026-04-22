using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Configuration;

public sealed class ProxyEndpointMatcherTests
{
    [Fact]
    public void IsProxyRequest_ReturnsFalse_WhenRequestPathIsEmpty()
    {
        var matcher = new ProxyEndpointMatcher([]);
        var context = new DefaultHttpContext();

        var result = matcher.IsProxyRequest(context.Request);

        Assert.False(result);
    }

    [Fact]
    public async Task IsProxyRequest_ReturnsTrue_WhenProxyEndpointMatchesTemplate()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/proxy/session/check";
        var matcher = TestFactories.CreateProxyEndpointMatcher(await CreateRouteEndpointAsync("/proxy/{**catchall}", addProxyMetadata: true));

        var result = matcher.IsProxyRequest(context.Request);

        Assert.True(result);
    }

    [Fact]
    public async Task IsProxyRequest_ReturnsFalse_WhenMatchingRouteLacksProxyMetadata()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/proxy/session/check";
        var matcher = TestFactories.CreateProxyEndpointMatcher(await CreateRouteEndpointAsync("/proxy/{**catchall}", addProxyMetadata: false));

        var result = matcher.IsProxyRequest(context.Request);

        Assert.False(result);
    }

    [Fact]
    public async Task IsProxyRequest_ReturnsTrue_WhenAnyDataSourceMatches()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/transport/socket";
        var matcher = new ProxyEndpointMatcher(
        [
            new TestEndpointDataSource(await CreateRouteEndpointAsync("/proxy/{**catchall}", addProxyMetadata: true)),
            new TestEndpointDataSource(await CreateRouteEndpointAsync("/transport/{**catchall}", addProxyMetadata: true))
        ]);

        var result = matcher.IsProxyRequest(context.Request);

        Assert.True(result);
    }

    private static async Task<Endpoint> CreateRouteEndpointAsync(string pattern, bool addProxyMetadata)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        var endpointBuilder = app.MapGet(pattern, static () => "ok");
        if (addProxyMetadata)
        {
            endpointBuilder.AsProxyEndpoint();
        }

        await app.StartAsync(TestContext.Current.CancellationToken);
        try
        {
            return Assert.Single(app.Services.GetRequiredService<IEnumerable<EndpointDataSource>>()
                .SelectMany(static dataSource => dataSource.Endpoints));
        }
        finally
        {
            await app.DisposeAsync();
        }
    }
}
