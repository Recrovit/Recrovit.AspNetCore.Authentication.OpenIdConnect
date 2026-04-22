using System.ComponentModel.DataAnnotations;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Settings for distributed user token caching, where token payloads are encrypted before being written to the distributed cache.
/// </summary>
public sealed class TokenCacheOptions
{
    /// <summary>
    /// Configuration section name.
    /// </summary>
    public const string SectionName = "TokenCache";

    /// <summary>
    /// Gets the prefix used for distributed cache keys that hold encrypted token payloads.
    /// </summary>
    [Required]
    public string CacheKeyPrefix { get; init; } = "oidc-user-token-cache";

    /// <summary>
    /// Gets how many seconds before expiry token refresh should start.
    /// </summary>
    [Range(0, 3600)]
    public int RefreshBeforeExpirationSeconds { get; init; } = 60;
}
