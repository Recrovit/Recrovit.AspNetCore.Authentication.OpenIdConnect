namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Defines the startup validation strictness for Data Protection configuration.
/// </summary>
public enum DataProtectionSecurityProfile
{
    /// <summary>
    /// Preserves backward-compatible behavior and emits warnings instead of startup failures.
    /// </summary>
    Standard = 0,

    /// <summary>
    /// Requires explicit application isolation and key-ring encryption for hardened deployments.
    /// </summary>
    Hardened = 1
}
