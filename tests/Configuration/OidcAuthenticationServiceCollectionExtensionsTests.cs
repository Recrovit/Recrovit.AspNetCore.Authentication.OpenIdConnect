using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Configuration;

public sealed class OidcAuthenticationServiceCollectionExtensionsTests
{
    [Fact]
    public void AddOidcAuthenticationInfrastructure_ValidatesSessionValidationDownstreamApiName()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Host:SessionValidationDownstreamApiName"] = "MissingApi",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:BaseUrl"] = "https://api.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:Scopes:0"] = "openid"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var ex = Assert.Throws<OptionsValidationException>(() =>
            serviceProvider.GetRequiredService<IOptions<OidcAuthenticationOptions>>().Value);

        Assert.Contains("SessionValidationDownstreamApiName", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_BindsRemoteFailureRedirectPath()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Host:RemoteFailureRedirectPath"] = "/safe-landing"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var options = serviceProvider.GetRequiredService<IOptions<OidcAuthenticationOptions>>().Value;

        Assert.Equal("/safe-landing", options.RemoteFailureRedirectPath);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_UsesDefaultRemoteFailureRedirectPath()
    {
        var configuration = TestConfiguration.Build();

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var options = serviceProvider.GetRequiredService<IOptions<OidcAuthenticationOptions>>().Value;

        Assert.Equal("/", options.RemoteFailureRedirectPath);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_UsesDefaultSessionTimeoutPolicy()
    {
        var configuration = TestConfiguration.Build();

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var options = serviceProvider.GetRequiredService<IOptions<OidcAuthenticationOptions>>().Value;

        Assert.Equal(TimeSpan.FromMinutes(20), options.SessionIdleTimeout);
        Assert.Equal(TimeSpan.FromHours(8), options.SessionAbsoluteTimeout);
        Assert.True(options.EnableSlidingExpiration);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_BindsConfiguredSessionTimeoutPolicy()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Host:SessionIdleTimeout"] = "00:30:00",
            [$"{TestConfiguration.RootSectionName}:Host:SessionAbsoluteTimeout"] = "12:00:00",
            [$"{TestConfiguration.RootSectionName}:Host:EnableSlidingExpiration"] = "false"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var options = serviceProvider.GetRequiredService<IOptions<OidcAuthenticationOptions>>().Value;

        Assert.Equal(TimeSpan.FromMinutes(30), options.SessionIdleTimeout);
        Assert.Equal(TimeSpan.FromHours(12), options.SessionAbsoluteTimeout);
        Assert.False(options.EnableSlidingExpiration);
    }

    [Theory]
    [InlineData("00:00:00", "08:00:00", "SessionIdleTimeout")]
    [InlineData("00:20:00", "00:00:00", "SessionAbsoluteTimeout")]
    [InlineData("00:30:00", "00:20:00", "SessionAbsoluteTimeout")]
    public void AddOidcAuthenticationInfrastructure_ValidatesSessionTimeoutPolicy(
        string sessionIdleTimeout,
        string sessionAbsoluteTimeout,
        string expectedMessagePart)
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Host:SessionIdleTimeout"] = sessionIdleTimeout,
            [$"{TestConfiguration.RootSectionName}:Host:SessionAbsoluteTimeout"] = sessionAbsoluteTimeout
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var ex = Assert.Throws<OptionsValidationException>(() =>
            serviceProvider.GetRequiredService<IOptions<OidcAuthenticationOptions>>().Value);

        Assert.Contains(expectedMessagePart, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_ValidatesRemoteFailureRedirectPath()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Host:RemoteFailureRedirectPath"] = "https://evil.example"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var ex = Assert.Throws<OptionsValidationException>(() =>
            serviceProvider.GetRequiredService<IOptions<OidcAuthenticationOptions>>().Value);

        Assert.Contains("RemoteFailureRedirectPath", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_Starts_WhenDownstreamApisMissing()
    {
        var configuration = TestConfiguration.Build();

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var catalog = serviceProvider.GetRequiredService<DownstreamApiCatalog>();
        var options = serviceProvider.GetRequiredService<IOptions<OidcProviderOptions>>().Value;

        Assert.Empty(catalog.Apis);
        Assert.Equal("https://idp.example.com", options.Authority);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_RegistersDownstreamProxyClients()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:BaseUrl"] = "https://api.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:SessionValidationApi:Scopes:0"] = "openid"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();

        Assert.NotNull(serviceProvider.GetService<IDownstreamHttpProxyClient>());
        Assert.NotNull(serviceProvider.GetService<IDownstreamTransportProxyClient>());
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_RegistersEncryptedTokenStoreDependencies()
    {
        var configuration = TestConfiguration.Build();

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();

        Assert.NotNull(serviceProvider.GetService<IDownstreamUserTokenStore>());
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_MapsCookieSessionTimeoutPolicy()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Host:CookieName"] = "__Host-Custom",
            [$"{TestConfiguration.RootSectionName}:Host:SessionIdleTimeout"] = "00:45:00",
            [$"{TestConfiguration.RootSectionName}:Host:EnableSlidingExpiration"] = "false"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var cookieOptions = serviceProvider
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);

        Assert.Equal("__Host-Custom", cookieOptions.Cookie.Name);
        Assert.True(cookieOptions.Cookie.HttpOnly);
        Assert.Equal(SameSiteMode.Lax, cookieOptions.Cookie.SameSite);
        Assert.Equal(CookieSecurePolicy.Always, cookieOptions.Cookie.SecurePolicy);
        Assert.Equal(TimeSpan.FromMinutes(45), cookieOptions.ExpireTimeSpan);
        Assert.False(cookieOptions.SlidingExpiration);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_AllowsDownstreamScopesOutsideProviderScopes()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:Scopes:0"] = "openid",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:GraphApi:BaseUrl"] = "https://graph.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:GraphApi:Scopes:0"] = "graph.read"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var exception = Record.Exception(() => RunStartupFilters(serviceProvider));

        Assert.Null(exception);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_UsesUnionOfProviderAndApiScopesForLogin()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:Scopes:0"] = "openid",
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:Scopes:1"] = "profile",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:GraphApi:BaseUrl"] = "https://graph.example.com",
            [$"{TestConfiguration.RootSectionName}:DownstreamApis:GraphApi:Scopes:0"] = "graph.read"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var oidcOptions = serviceProvider.GetRequiredService<IOptionsMonitor<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>>()
            .Get(Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectDefaults.AuthenticationScheme);

        Assert.Equal(["graph.read", "openid", "profile"], oidcOptions.Scope.OrderBy(scope => scope, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task AddOidcAuthenticationInfrastructure_ForwardsDomainHintOnRedirectToIdentityProvider()
    {
        var configuration = TestConfiguration.Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var oidcOptions = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);
        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };
        var properties = new AuthenticationProperties();
        properties.Items[AuthenticationEndpoints.DomainHintParameterName] = "contoso.com";
        var context = new RedirectContext(
            httpContext,
            new AuthenticationScheme(OpenIdConnectDefaults.AuthenticationScheme, null, typeof(PassThroughAuthenticationHandler)),
            oidcOptions,
            properties);

        await oidcOptions.Events.RedirectToIdentityProvider(context);

        Assert.Equal(
            "contoso.com",
            context.ProtocolMessage.Parameters[AuthenticationEndpoints.DomainHintParameterName]);
    }

    [Fact]
    public async Task AddOidcAuthenticationInfrastructure_DoesNotSetEmptyDomainHintOnRedirectToIdentityProvider()
    {
        var configuration = TestConfiguration.Build();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var oidcOptions = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);
        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };
        var properties = new AuthenticationProperties();
        properties.Items[AuthenticationEndpoints.DomainHintParameterName] = "   ";
        var context = new RedirectContext(
            httpContext,
            new AuthenticationScheme(OpenIdConnectDefaults.AuthenticationScheme, null, typeof(PassThroughAuthenticationHandler)),
            oidcOptions,
            properties);

        await oidcOptions.Events.RedirectToIdentityProvider(context);

        Assert.False(context.ProtocolMessage.Parameters.ContainsKey(AuthenticationEndpoints.DomainHintParameterName));
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_BindsConfiguredProvider()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Provider"] = "AzureADB2C",
            [$"{TestConfiguration.RootSectionName}:Providers:AzureADB2C:Authority"] = "https://b2c.example.com",
            [$"{TestConfiguration.RootSectionName}:Providers:AzureADB2C:ClientId"] = "b2c-client-id",
            [$"{TestConfiguration.RootSectionName}:Providers:AzureADB2C:ClientSecret"] = "b2c-client-secret",
            [$"{TestConfiguration.RootSectionName}:Providers:AzureADB2C:Scopes:0"] = "openid",
            [$"{TestConfiguration.RootSectionName}:Providers:AzureADB2C:Scopes:1"] = "profile"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var options = serviceProvider.GetRequiredService<IOptions<OidcProviderOptions>>().Value;

        Assert.Equal("https://b2c.example.com", options.Authority);
        Assert.Equal("b2c-client-id", options.ClientId);
        Assert.Equal(["openid", "profile"], options.Scopes);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_RegistersActiveProviderOptions()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Provider"] = "AzureADB2C",
            [$"{TestConfiguration.RootSectionName}:Providers:AzureADB2C:Authority"] = "https://b2c.example.com",
            [$"{TestConfiguration.RootSectionName}:Providers:AzureADB2C:ClientId"] = "b2c-client-id",
            [$"{TestConfiguration.RootSectionName}:Providers:AzureADB2C:ClientSecret"] = "b2c-client-secret",
            [$"{TestConfiguration.RootSectionName}:Providers:AzureADB2C:Scopes:0"] = "openid"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();
        var options = serviceProvider.GetRequiredService<IOptions<ActiveOidcProviderOptions>>().Value;

        Assert.Equal("AzureADB2C", options.ProviderName);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_Throws_WhenProviderMissing()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Provider"] = null
        });

        var services = new ServiceCollection();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment()));

        Assert.Contains($"{TestConfiguration.RootSectionName}:Provider", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_Throws_WhenProviderSectionMissing()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Provider"] = "MissingProvider"
        });

        var services = new ServiceCollection();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment()));

        Assert.Contains($"{TestConfiguration.RootSectionName}:Providers:MissingProvider", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_ThrowsOnStartup_WhenProductionAuthorityIsNotHttps()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:Authority"] = "http://idp.example.com",
            [$"{TestConfiguration.RootSectionName}:Infrastructure:DataProtectionKeysPath"] = "/keys"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(
            configuration,
            new FakeWebHostEnvironment { EnvironmentName = Environments.Production });

        using var serviceProvider = services.BuildServiceProvider();

        var ex = Assert.Throws<InvalidOperationException>(() => RunStartupFilters(serviceProvider));

        Assert.Contains($"{TestConfiguration.RootSectionName}:Providers:<provider>:Authority", ex.Message, StringComparison.Ordinal);
        Assert.Contains("absolute HTTPS URI", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_AllowsNonHttpsAuthorityOutsideProduction()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:Authority"] = "http://idp.example.com"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(
            configuration,
            new FakeWebHostEnvironment { EnvironmentName = Environments.Development });

        using var serviceProvider = services.BuildServiceProvider();

        var exception = Record.Exception(() => RunStartupFilters(serviceProvider));

        Assert.Null(exception);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_ThrowsOnStartup_WhenProductionForwardedHeadersEnabledWithoutTrustedProxies()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Infrastructure:ForwardedHeadersEnabled"] = bool.TrueString,
            [$"{TestConfiguration.RootSectionName}:Infrastructure:DataProtectionKeysPath"] = "/keys"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(
            configuration,
            new FakeWebHostEnvironment { EnvironmentName = Environments.Production });
        ReplaceDistributedCache(services);

        using var serviceProvider = services.BuildServiceProvider();

        var ex = Assert.Throws<InvalidOperationException>(() => RunStartupFilters(serviceProvider));

        Assert.Contains($"{TestConfiguration.RootSectionName}:Infrastructure:KnownProxies", ex.Message, StringComparison.Ordinal);
        Assert.Contains($"{TestConfiguration.RootSectionName}:Infrastructure:KnownNetworks", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_AllowsProductionForwardedHeaders_WhenKnownProxyConfigured()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Infrastructure:ForwardedHeadersEnabled"] = bool.TrueString,
            [$"{TestConfiguration.RootSectionName}:Infrastructure:KnownProxies:0"] = "10.0.0.10",
            [$"{TestConfiguration.RootSectionName}:Infrastructure:DataProtectionKeysPath"] = "/keys"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(
            configuration,
            new FakeWebHostEnvironment { EnvironmentName = Environments.Production });
        ReplaceDistributedCache(services);

        using var serviceProvider = services.BuildServiceProvider();

        var exception = Record.Exception(() => RunStartupFilters(serviceProvider));

        Assert.Null(exception);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_AllowsProductionForwardedHeaders_WhenKnownNetworkConfigured()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Infrastructure:ForwardedHeadersEnabled"] = bool.TrueString,
            [$"{TestConfiguration.RootSectionName}:Infrastructure:KnownNetworks:0"] = "10.0.0.0/24",
            [$"{TestConfiguration.RootSectionName}:Infrastructure:DataProtectionKeysPath"] = "/keys"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(
            configuration,
            new FakeWebHostEnvironment { EnvironmentName = Environments.Production });
        ReplaceDistributedCache(services);

        using var serviceProvider = services.BuildServiceProvider();

        var exception = Record.Exception(() => RunStartupFilters(serviceProvider));

        Assert.Null(exception);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_AllowsProduction_WhenForwardedHeadersDisabledWithoutTrustedProxies()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Infrastructure:ForwardedHeadersEnabled"] = bool.FalseString,
            [$"{TestConfiguration.RootSectionName}:Infrastructure:DataProtectionKeysPath"] = "/keys"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(
            configuration,
            new FakeWebHostEnvironment { EnvironmentName = Environments.Production });
        ReplaceDistributedCache(services);

        using var serviceProvider = services.BuildServiceProvider();

        var exception = Record.Exception(() => RunStartupFilters(serviceProvider));

        Assert.Null(exception);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_Throws_WhenKnownProxyIsInvalid()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Infrastructure:KnownProxies:0"] = "not-an-ip"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();

        var ex = Assert.Throws<OptionsValidationException>(() =>
            serviceProvider.GetRequiredService<IOptions<HostSecurityOptions>>().Value);

        Assert.Contains($"{TestConfiguration.RootSectionName}:Infrastructure:KnownProxies", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AddOidcAuthenticationInfrastructure_Throws_WhenKnownNetworkIsInvalid()
    {
        var configuration = TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Infrastructure:KnownNetworks:0"] = "10.0.0.0/not-a-prefix"
        });

        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(configuration, new FakeWebHostEnvironment());

        using var serviceProvider = services.BuildServiceProvider();

        var ex = Assert.Throws<OptionsValidationException>(() =>
            serviceProvider.GetRequiredService<IOptions<HostSecurityOptions>>().Value);

        Assert.Contains($"{TestConfiguration.RootSectionName}:Infrastructure:KnownNetworks", ex.Message, StringComparison.Ordinal);
    }

    private static void RunStartupFilters(IServiceProvider serviceProvider)
    {
        var startupFilters = serviceProvider.GetServices<IStartupFilter>().ToArray();
        Action<IApplicationBuilder> pipeline = static _ => { };

        foreach (var startupFilter in startupFilters.Reverse())
        {
            pipeline = startupFilter.Configure(pipeline);
        }

        pipeline(new ApplicationBuilder(serviceProvider));
    }

    private static void ReplaceDistributedCache(ServiceCollection services)
    {
        services.RemoveAll<Microsoft.Extensions.Caching.Distributed.IDistributedCache>();
        services.AddSingleton<Microsoft.Extensions.Caching.Distributed.IDistributedCache, StubDistributedCache>();
    }
}
