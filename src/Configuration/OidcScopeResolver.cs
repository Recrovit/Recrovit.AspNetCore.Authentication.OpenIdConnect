namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Resolves effective login scopes and downstream API scope requirements.
/// </summary>
internal sealed class OidcScopeResolver
{
    private readonly IReadOnlyDictionary<string, string[]> apiScopes;

    public OidcScopeResolver(string[] providerScopes, DownstreamApiCatalog downstreamApiCatalog)
    {
        ArgumentNullException.ThrowIfNull(providerScopes);
        ArgumentNullException.ThrowIfNull(downstreamApiCatalog);

        apiScopes = downstreamApiCatalog.Apis.ToDictionary(
            pair => pair.Key,
            pair => NormalizeScopes(pair.Value.Scopes),
            StringComparer.OrdinalIgnoreCase);

        EffectiveLoginScopes = NormalizeScopes(
            [.. providerScopes, .. downstreamApiCatalog.Apis.SelectMany(api => api.Value.Scopes)]);
    }

    public string[] EffectiveLoginScopes { get; }

    public string[] GetRequiredApiScopes(string downstreamApiName)
    {
        if (!apiScopes.TryGetValue(downstreamApiName, out var scopes))
        {
            throw new InvalidOperationException($"The downstream API '{downstreamApiName}' is not configured.");
        }

        return scopes;
    }

    public static string[] NormalizeScopes(IEnumerable<string> scopes)
    {
        return scopes
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .Select(scope => scope.Trim())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(scope => scope, StringComparer.Ordinal)
            .ToArray();
    }
}
