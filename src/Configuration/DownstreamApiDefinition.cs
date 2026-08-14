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
    /// Gets a value indicating whether the default forwarded request headers are included for this downstream API.
    /// </summary>
    public bool IncludeDefaultForwardedRequestHeaders { get; init; } = true;

    /// <summary>
    /// Gets the request headers that may be forwarded to the downstream API.
    /// </summary>
    public string[] ForwardedRequestHeaders { get; init; } = [];

    /// <summary>
    /// Gets the response headers that may be forwarded from the downstream API in addition to the default allowlist.
    /// </summary>
    public string[] ForwardedResponseHeaders { get; init; } = [];

    /// <summary>
    /// Gets the relative path appended to the base URL.
    /// </summary>
    public string RelativePath { get; init; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether the downstream API is disabled.
    /// </summary>
    public bool Disabled { get; init; }
}
