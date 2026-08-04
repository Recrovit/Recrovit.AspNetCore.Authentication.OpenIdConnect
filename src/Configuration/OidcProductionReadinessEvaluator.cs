using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

internal static class OidcProductionReadinessEvaluator
{
    public static bool IsEnforced(IHostEnvironment environment, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var hostSecurityOptions = OpenIdConnectConfigurationResolver
            .GetInfrastructureSection(configuration)
            .Get<HostSecurityOptions>() ?? new HostSecurityOptions();

        return IsEnforced(environment, hostSecurityOptions);
    }

    public static bool IsEnforced(IHostEnvironment environment, HostSecurityOptions hostSecurityOptions)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(hostSecurityOptions);

        return environment.IsProduction() ||
            (environment.IsDevelopment() && hostSecurityOptions.RequireProductionReadinessInDevelopment);
    }
}
