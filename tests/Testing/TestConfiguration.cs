using Microsoft.Extensions.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;

internal static class TestConfiguration
{
    public const string RootSectionName = "Recrovit:OpenIdConnect";

    public static IConfiguration Build(Dictionary<string, string?>? overrides = null)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(CreateBaseConfiguration(overrides))
            .Build();
    }

    public static Dictionary<string, string?> CreateBaseConfiguration(Dictionary<string, string?>? overrides = null)
    {
        var values = new Dictionary<string, string?>
        {
            [$"{RootSectionName}:Host:CookieName"] = "__Host-Test",
            [$"{RootSectionName}:Host:EndpointBasePath"] = "/authentication",
            [$"{RootSectionName}:Provider"] = "Duende",
            [$"{RootSectionName}:Providers:Duende:Authority"] = "https://idp.example.com",
            [$"{RootSectionName}:Providers:Duende:ClientId"] = "client-id",
            [$"{RootSectionName}:Providers:Duende:ClientSecret"] = "client-secret",
            [$"{RootSectionName}:Providers:Duende:CallbackPath"] = "/signin-oidc",
            [$"{RootSectionName}:Providers:Duende:SignedOutCallbackPath"] = "/signout-callback-oidc",
            [$"{RootSectionName}:Providers:Duende:RemoteSignOutPath"] = "/signout-oidc",
            [$"{RootSectionName}:Providers:Duende:SignedOutRedirectPath"] = "/",
            [$"{RootSectionName}:Providers:Duende:Scopes:0"] = "openid",
            [$"{RootSectionName}:TokenCache:CacheKeyPrefix"] = "test-cache"
        };

        if (overrides is null)
        {
            return values;
        }

        foreach (var (key, value) in overrides)
        {
            if (value is null)
            {
                values.Remove(key);
            }
            else
            {
                values[key] = value;
            }
        }

        return values;
    }
}
