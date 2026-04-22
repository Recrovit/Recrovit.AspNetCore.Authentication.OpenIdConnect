namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Host-level security settings used by the authentication infrastructure.
/// </summary>
public sealed class HostSecurityOptions
{
    /// <summary>
    /// Configuration section name.
    /// </summary>
    public const string SectionName = "Infrastructure";

    /// <summary>
    /// Gets a value indicating whether forwarded proxy headers are enabled.
    /// </summary>
    public bool ForwardedHeadersEnabled { get; init; }

    /// <summary>
    /// Gets the trusted reverse proxy IP addresses allowed to supply forwarded headers.
    /// </summary>
    public string[] KnownProxies { get; init; } = [];

    /// <summary>
    /// Gets the trusted reverse proxy networks allowed to supply forwarded headers.
    /// </summary>
    public string[] KnownNetworks { get; init; } = [];

    /// <summary>
    /// Gets the shared path for persisted Data Protection keys used to decrypt encrypted token-cache entries across hosts.
    /// </summary>
    public string? DataProtectionKeysPath { get; init; }
}
