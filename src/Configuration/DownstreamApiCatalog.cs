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
    /// <param name="configuration">The application configuration.</param>
    /// <returns>A validated catalog of downstream API definitions.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the downstream API configuration is missing or invalid.</exception>
    public static DownstreamApiCatalog Create(IConfigurationSection configuration)
    {
        var definitions = configuration
            .Get<Dictionary<string, DownstreamApiDefinition>>() ?? [];

        foreach (var (name, definition) in definitions)
        {
            if (string.IsNullOrWhiteSpace(definition.BaseUrl))
            {
                throw new InvalidOperationException($"{configuration.Path}:{name}:BaseUrl is required.");
            }

            if (!Uri.TryCreate(definition.BaseUrl, UriKind.Absolute, out _))
            {
                throw new InvalidOperationException($"{configuration.Path}:{name}:BaseUrl must be a valid absolute URL.");
            }

            if (definition.Scopes.Length == 0 || definition.Scopes.Any(string.IsNullOrWhiteSpace))
            {
                throw new InvalidOperationException($"{configuration.Path}:{name}:Scopes must contain at least one non-empty scope.");
            }
        }

        return new DownstreamApiCatalog(new ReadOnlyDictionary<string, DownstreamApiDefinition>(
            new Dictionary<string, DownstreamApiDefinition>(definitions, StringComparer.OrdinalIgnoreCase)));
    }
}
