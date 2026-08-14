namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Stores the full token state for an authenticated local session.
/// </summary>
public sealed class OidcSessionState
{
    /// <summary>
    /// Gets the stored OIDC session tokens for the authenticated session.
    /// </summary>
    public StoredOidcSessionTokenSet? SessionTokens { get; set; }

    /// <summary>
    /// Gets the cached downstream API tokens keyed by normalized API/scope identity.
    /// </summary>
    public Dictionary<string, CachedDownstreamApiTokenEntry> ApiTokens { get; set; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets when the token state was last updated by a refresh exchange.
    /// </summary>
    public DateTimeOffset? LastRefreshUtc { get; set; }

    internal OidcSessionState Clone()
    {
        return new OidcSessionState
        {
            SessionTokens = SessionTokens?.Clone(),
            ApiTokens = ApiTokens.ToDictionary(
                entry => entry.Key,
                entry => entry.Value.Clone(),
                StringComparer.Ordinal),
            LastRefreshUtc = LastRefreshUtc
        };
    }
}
