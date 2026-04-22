using Microsoft.Extensions.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Resolves the OpenID Connect infrastructure configuration sections.
/// </summary>
internal static class OpenIdConnectConfigurationResolver
{
    public const string RootSectionName = "Recrovit:OpenIdConnect";

    private const string ProviderKey = "Provider";
    private const string ProvidersSectionName = "Providers";
    private const string DownstreamApisSectionName = "DownstreamApis";

    public static IConfigurationSection GetRootSection(IConfiguration configuration)
        => configuration.GetSection(RootSectionName);

    public static IConfigurationSection GetHostSection(IConfiguration configuration)
        => GetRootSection(configuration).GetSection(OidcAuthenticationOptions.SectionName);

    public static IConfigurationSection GetTokenCacheSection(IConfiguration configuration)
        => GetRootSection(configuration).GetSection(TokenCacheOptions.SectionName);

    public static IConfigurationSection GetInfrastructureSection(IConfiguration configuration)
        => GetRootSection(configuration).GetSection(HostSecurityOptions.SectionName);

    public static IConfigurationSection GetDownstreamApisSection(IConfiguration configuration)
        => GetRootSection(configuration).GetSection(DownstreamApisSectionName);

    public static string GetActiveProviderName(IConfiguration configuration)
    {
        var providerName = GetRootSection(configuration).GetValue<string>(ProviderKey);
        if (string.IsNullOrWhiteSpace(providerName))
        {
            throw new InvalidOperationException($"{RootSectionName}:Provider is required.");
        }

        return providerName;
    }

    public static IConfigurationSection GetActiveProviderSection(IConfiguration configuration)
    {
        var rootSection = GetRootSection(configuration);
        var providerName = GetActiveProviderName(configuration);
        var providerSection = rootSection.GetSection(ProvidersSectionName).GetSection(providerName);
        if (!providerSection.Exists())
        {
            throw new InvalidOperationException(
                $"{RootSectionName}:Providers:{providerName} is required for the configured provider.");
        }

        return providerSection;
    }
}
