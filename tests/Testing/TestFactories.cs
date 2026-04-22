using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;

internal static class TestFactories
{
    public static DownstreamApiCatalog CreateDownstreamApiCatalog(string relativePath = "session-check")
    {
        return new DownstreamApiCatalog(new Dictionary<string, DownstreamApiDefinition>(StringComparer.OrdinalIgnoreCase)
        {
            ["SessionValidationApi"] = new()
            {
                BaseUrl = "https://api.example.com",
                Scopes = ["openid"],
                RelativePath = relativePath
            },
            ["GraphApi"] = new()
            {
                BaseUrl = "https://graph.example.com",
                Scopes = ["graph.read"],
                RelativePath = "graph"
            }
        });
    }

    public static OidcProviderOptions CreateOidcProviderOptions()
    {
        return new OidcProviderOptions
        {
            ClientId = "client-id",
            ClientSecret = "client-secret",
            Scopes = ["openid", "profile"],
            Authority = "https://idp.example.com"
        };
    }

    public static TokenCacheOptions CreateTokenCacheOptions()
    {
        return new TokenCacheOptions
        {
            RefreshBeforeExpirationSeconds = 60,
            CacheKeyPrefix = "test-cache"
        };
    }

    public static IDownstreamUserTokenProvider CreateProvider(
        InMemoryTokenStore tokenStore,
        IHttpClientFactory httpClientFactory,
        FakeWebHostEnvironment? environment = null,
        ILoggerFactory? loggerFactory = null,
        IOptionsMonitor<OpenIdConnectOptions>? openIdOptionsMonitor = null)
    {
        var services = new ServiceCollection();
        environment ??= new FakeWebHostEnvironment();
        services.AddLogging();
        services.AddOidcAuthenticationInfrastructure(TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:BaseUrl"] = "https://api.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:Scopes:0"] = "openid",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:GraphApi:BaseUrl"] = "https://graph.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:GraphApi:Scopes:0"] = "graph.read"
        }), environment);
        services.Replace(ServiceDescriptor.Scoped<IDownstreamUserTokenStore>(_ => tokenStore));
        services.Replace(ServiceDescriptor.Singleton(httpClientFactory));
        services.Replace(ServiceDescriptor.Singleton<IOptionsMonitor<OpenIdConnectOptions>>(openIdOptionsMonitor ?? new StaticOptionsMonitor<OpenIdConnectOptions>(new OpenIdConnectOptions
        {
            ConfigurationManager = new StaticConfigurationManager("https://idp.example.com/connect/token")
        })));

        if (loggerFactory is not null)
        {
            services.Replace(ServiceDescriptor.Singleton(loggerFactory));
        }

        return services.BuildServiceProvider().GetRequiredService<IDownstreamUserTokenProvider>();
    }

    public static DownstreamHttpProxyClient CreateHttpProxyClient(HttpClient httpClient, IDownstreamUserTokenProvider tokenProvider)
    {
        return CreateHttpProxyClient(httpClient, tokenProvider, NullLogger<DownstreamHttpProxyClient>.Instance);
    }

    public static DownstreamHttpProxyClient CreateHttpProxyClient(
        HttpClient httpClient,
        IDownstreamUserTokenProvider tokenProvider,
        ILogger<DownstreamHttpProxyClient> logger)
    {
        return new DownstreamHttpProxyClient(
            logger,
            httpClient,
            tokenProvider,
            CreateDownstreamApiCatalog(relativePath: "gateway"));
    }

    public static Endpoint CreateEndpoint(params object[] metadata)
    {
        var builder = new RouteEndpointBuilder(static _ => Task.CompletedTask, RoutePatternFactory.Parse("/test"), 0);
        foreach (var item in metadata)
        {
            builder.Metadata.Add(item);
        }

        return builder.Build();
    }

    public static ProxyEndpointMatcher CreateProxyEndpointMatcher(params Endpoint[] endpoints)
    {
        return new ProxyEndpointMatcher([new TestEndpointDataSource(endpoints)]);
    }
}
