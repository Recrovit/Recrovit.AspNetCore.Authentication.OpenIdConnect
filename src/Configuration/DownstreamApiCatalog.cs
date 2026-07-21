using System.Collections.ObjectModel;
using Microsoft.Extensions.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Catalog of downstream API definitions loaded from configuration.
/// </summary>
public sealed class DownstreamApiCatalog
{
    private readonly IReadOnlyDictionary<string, DownstreamApiDefinition> apis;

    /// <summary>
    /// Initializes a new catalog instance.
    /// </summary>
    /// <param name="apis">The downstream APIs indexed by logical name.</param>
    public DownstreamApiCatalog(IReadOnlyDictionary<string, DownstreamApiDefinition> apis)
    {
        this.apis = apis;
    }

    /// <summary>
    /// Gets the configured downstream APIs.
    /// </summary>
    public IReadOnlyDictionary<string, DownstreamApiDefinition> Apis => apis;

    /// <summary>
    /// Gets the named downstream API definition.
    /// </summary>
    /// <param name="name">The logical downstream API name.</param>
    /// <returns>The configured downstream API definition.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the requested downstream API is not configured.</exception>
    public DownstreamApiDefinition GetRequired(string name)
    {
        if (!apis.TryGetValue(name, out var definition))
        {
            throw new InvalidOperationException($"The downstream API '{name}' is not configured.");
        }

        return definition;
    }

    /// <summary>
    /// Creates and validates a downstream API catalog from configuration.
    /// </summary>
    /// <param name="sharedConfiguration">The shared downstream API configuration.</param>
    /// <param name="providerConfiguration">The active provider-specific downstream API configuration.</param>
    /// <returns>A validated catalog of downstream API definitions.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the downstream API configuration is missing or invalid.</exception>
    public static DownstreamApiCatalog Create(
        IConfigurationSection sharedConfiguration,
        IConfigurationSection? providerConfiguration = null)
    {
        var sharedDefinitions = ReadDefinitions(sharedConfiguration);
        var providerDefinitions = providerConfiguration is null
            ? new Dictionary<string, ConfiguredDownstreamApi>(StringComparer.OrdinalIgnoreCase)
            : ReadDefinitions(providerConfiguration);
        var names = new HashSet<string>(sharedDefinitions.Keys, StringComparer.OrdinalIgnoreCase);
        names.UnionWith(providerDefinitions.Keys);
        var effectiveDefinitions = new Dictionary<string, DownstreamApiDefinition>(StringComparer.OrdinalIgnoreCase);

        foreach (var name in names)
        {
            sharedDefinitions.TryGetValue(name, out var sharedDefinition);
            providerDefinitions.TryGetValue(name, out var providerDefinition);
            var definition = MergeDefinition(sharedDefinition, providerDefinition);
            if (definition.Disabled)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(definition.BaseUrl))
            {
                var sourcePath = GetPrimaryDefinitionPath(sharedConfiguration, providerConfiguration, name, sharedDefinition, providerDefinition);
                throw new InvalidOperationException($"{sourcePath}:BaseUrl is required.");
            }

            if (!Uri.TryCreate(definition.BaseUrl, UriKind.Absolute, out _))
            {
                var sourcePath = GetPrimaryDefinitionPath(sharedConfiguration, providerConfiguration, name, sharedDefinition, providerDefinition);
                throw new InvalidOperationException($"{sourcePath}:BaseUrl must be a valid absolute URL.");
            }

            if (definition.Scopes.Length == 0 || definition.Scopes.Any(string.IsNullOrWhiteSpace))
            {
                var sourcePath = providerDefinition?.HasScopesSection is true
                    ? providerConfiguration!.GetSection(name).Path
                    : GetPrimaryDefinitionPath(sharedConfiguration, providerConfiguration, name, sharedDefinition, providerDefinition);
                throw new InvalidOperationException($"{sourcePath}:Scopes must contain at least one non-empty scope.");
            }

            effectiveDefinitions[name] = definition;
        }

        return new DownstreamApiCatalog(new ReadOnlyDictionary<string, DownstreamApiDefinition>(
            effectiveDefinitions));
    }

    private static Dictionary<string, ConfiguredDownstreamApi> ReadDefinitions(IConfigurationSection configuration)
    {
        var definitions = new Dictionary<string, ConfiguredDownstreamApi>(StringComparer.OrdinalIgnoreCase);

        foreach (var child in configuration.GetChildren())
        {
            definitions[child.Key] = new ConfiguredDownstreamApi
            {
                BaseUrl = child[nameof(DownstreamApiDefinition.BaseUrl)],
                RelativePath = child[nameof(DownstreamApiDefinition.RelativePath)],
                Disabled = child.GetValue<bool?>(nameof(DownstreamApiDefinition.Disabled)),
                Scopes = child.GetSection(nameof(DownstreamApiDefinition.Scopes)).Exists()
                    ? child.GetSection(nameof(DownstreamApiDefinition.Scopes)).Get<string[]>()
                    : null,
                HasScopesSection = child.GetSection(nameof(DownstreamApiDefinition.Scopes)).Exists()
            };
        }

        return definitions;
    }

    private static DownstreamApiDefinition MergeDefinition(
        ConfiguredDownstreamApi? sharedDefinition,
        ConfiguredDownstreamApi? providerDefinition)
    {
        return new DownstreamApiDefinition
        {
            BaseUrl = !string.IsNullOrWhiteSpace(providerDefinition?.BaseUrl)
                ? providerDefinition.BaseUrl
                : sharedDefinition?.BaseUrl ?? string.Empty,
            RelativePath = providerDefinition?.RelativePath
                ?? sharedDefinition?.RelativePath
                ?? string.Empty,
            Scopes = providerDefinition?.HasScopesSection is true
                ? providerDefinition.Scopes ?? []
                : sharedDefinition?.Scopes ?? [],
            Disabled = providerDefinition?.Disabled ?? sharedDefinition?.Disabled ?? false
        };
    }

    private static string GetPrimaryDefinitionPath(
        IConfigurationSection sharedConfiguration,
        IConfigurationSection? providerConfiguration,
        string name,
        ConfiguredDownstreamApi? sharedDefinition,
        ConfiguredDownstreamApi? providerDefinition)
    {
        return providerDefinition is not null && sharedDefinition is null && providerConfiguration is not null
            ? providerConfiguration.GetSection(name).Path
            : sharedConfiguration.GetSection(name).Path;
    }

    private sealed class ConfiguredDownstreamApi
    {
        public string? BaseUrl { get; init; }

        public string[]? Scopes { get; init; }

        public string? RelativePath { get; init; }

        public bool? Disabled { get; init; }

        public bool HasScopesSection { get; init; }
    }
}
