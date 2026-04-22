namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Cached token data stored for an authenticated user and a specific downstream API.
/// </summary>
public sealed class CachedDownstreamApiTokenEntry
{
    /// <summary>
    /// Gets the access token.
    /// </summary>
    public string AccessToken { get; init; } = string.Empty;

    /// <summary>
    /// Gets the access token expiry in UTC.
    /// </summary>
    public DateTimeOffset ExpiresAtUtc { get; init; }
}
