using System.ComponentModel.DataAnnotations;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Holds the active OpenID Connect provider name selected for the host.
/// </summary>
public sealed class ActiveOidcProviderOptions
{
    /// <summary>
    /// Gets the configured active provider name.
    /// </summary>
    [Required]
    public string ProviderName { get; set; } = string.Empty;
}
