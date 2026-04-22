using Microsoft.Extensions.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Configuration;

public sealed class DownstreamApiCatalogTests
{
    private const string RootSectionName = "Recrovit:OpenIdConnect";

    [Fact]
    public void Create_ValidatesDefinitions()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{RootSectionName}:DownstreamApis:SessionValidationApi:BaseUrl"] = "https://example.com",
                [$"{RootSectionName}:DownstreamApis:SessionValidationApi:Scopes:0"] = "openid",
                [$"{RootSectionName}:DownstreamApis:SessionValidationApi:RelativePath"] = "session/check"
            })
            .Build();

        var catalog = DownstreamApiCatalog.Create(configuration.GetSection($"{RootSectionName}:DownstreamApis"));

        var api = catalog.GetRequired("sessionvalidationapi");
        Assert.Equal("https://example.com", api.BaseUrl);
        Assert.Equal("session/check", api.RelativePath);
        Assert.Equal(["openid"], api.Scopes);
    }

    [Fact]
    public void Create_ReturnsEmptyCatalog_WhenSectionMissing()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        var catalog = DownstreamApiCatalog.Create(configuration.GetSection($"{RootSectionName}:DownstreamApis"));

        Assert.Empty(catalog.Apis);
    }
}
