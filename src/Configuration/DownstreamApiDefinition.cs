using System.ComponentModel.DataAnnotations;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Describes the configuration needed to call a downstream API.
/// </summary>
public sealed class DownstreamApiDefinition
{
    /// <summary>
    /// Gets the absolute base URL of the downstream API.
    /// </summary>
    [Required]
    public string BaseUrl { get; init; } = string.Empty;

    /// <summary>
    /// Gets the scopes required for the downstream API call.
    /// </summary>
    public string[] Scopes { get; init; } = [];

    /// <summary>
    /// Gets the relative path appended to the base URL.
    /// </summary>
    public string RelativePath { get; init; } = string.Empty;
}
