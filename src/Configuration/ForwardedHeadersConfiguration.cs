using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Hosting;
using System.Net;
using SystemIPNetwork = System.Net.IPNetwork;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

internal static class ForwardedHeadersConfiguration
{
    private const string InfrastructureSectionPath = $"{OpenIdConnectConfigurationResolver.RootSectionName}:Infrastructure";

    public static string KnownProxiesConfigurationPath => $"{InfrastructureSectionPath}:KnownProxies";

    public static string KnownNetworksConfigurationPath => $"{InfrastructureSectionPath}:KnownNetworks";

    public static ForwardedHeadersOptions CreateOptions(HostSecurityOptions hostSecurityOptions)
    {
        ArgumentNullException.ThrowIfNull(hostSecurityOptions);

        var options = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
        };

        foreach (var proxy in GetKnownProxies(hostSecurityOptions))
        {
            options.KnownProxies.Add(proxy);
        }

        foreach (var network in GetKnownNetworks(hostSecurityOptions))
        {
            options.KnownIPNetworks.Add(network);
        }

        return options;
    }

    public static string? GetProductionRequirementError(HostSecurityOptions hostSecurityOptions, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(hostSecurityOptions);
        ArgumentNullException.ThrowIfNull(environment);

        if (!environment.IsProduction() || !hostSecurityOptions.ForwardedHeadersEnabled)
        {
            return null;
        }

        return HasTrustedProxyConfiguration(hostSecurityOptions)
            ? null
            : $"Production requires {KnownProxiesConfigurationPath} or {KnownNetworksConfigurationPath} when {InfrastructureSectionPath}:ForwardedHeadersEnabled is true.";
    }

    public static bool HasTrustedProxyConfiguration(HostSecurityOptions hostSecurityOptions)
    {
        ArgumentNullException.ThrowIfNull(hostSecurityOptions);

        return hostSecurityOptions.KnownProxies.Length > 0 || hostSecurityOptions.KnownNetworks.Length > 0;
    }

    public static bool AreKnownProxiesValid(HostSecurityOptions hostSecurityOptions)
    {
        ArgumentNullException.ThrowIfNull(hostSecurityOptions);

        return TryParseAll(hostSecurityOptions.KnownProxies, KnownProxiesConfigurationPath, static value => IPAddress.TryParse(value, out _));
    }

    public static bool AreKnownNetworksValid(HostSecurityOptions hostSecurityOptions)
    {
        ArgumentNullException.ThrowIfNull(hostSecurityOptions);

        return TryParseAll(hostSecurityOptions.KnownNetworks, KnownNetworksConfigurationPath, static value => SystemIPNetwork.TryParse(value, out _));
    }

    public static IReadOnlyList<IPAddress> GetKnownProxies(HostSecurityOptions hostSecurityOptions)
    {
        ArgumentNullException.ThrowIfNull(hostSecurityOptions);

        return ParseAll(
            hostSecurityOptions.KnownProxies,
            KnownProxiesConfigurationPath,
            static value => IPAddress.TryParse(value, out var address)
                ? address
                : throw new InvalidOperationException());
    }

    public static IReadOnlyList<SystemIPNetwork> GetKnownNetworks(HostSecurityOptions hostSecurityOptions)
    {
        ArgumentNullException.ThrowIfNull(hostSecurityOptions);

        return ParseAll(
            hostSecurityOptions.KnownNetworks,
            KnownNetworksConfigurationPath,
            static value => SystemIPNetwork.TryParse(value, out var network)
                ? network
                : throw new InvalidOperationException());
    }

    private static bool TryParseAll(
        IEnumerable<string> values,
        string configurationPath,
        Func<string, bool> isValid)
    {
        ArgumentNullException.ThrowIfNull(values);

        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value) || !isValid(value))
            {
                return false;
            }
        }

        return true;
    }

    private static IReadOnlyList<T> ParseAll<T>(
        IEnumerable<string> values,
        string configurationPath,
        Func<string, T> parser)
    {
        var parsedValues = new List<T>();

        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidOperationException($"Each entry in {configurationPath} must be a valid {(configurationPath.EndsWith("KnownProxies", StringComparison.Ordinal) ? "IP address" : "CIDR network")} value.");
            }

            try
            {
                parsedValues.Add(parser(value));
            }
            catch (InvalidOperationException)
            {
                throw new InvalidOperationException($"Each entry in {configurationPath} must be a valid {(configurationPath.EndsWith("KnownProxies", StringComparison.Ordinal) ? "IP address" : "CIDR network")} value.");
            }
        }

        return parsedValues;
    }
}
