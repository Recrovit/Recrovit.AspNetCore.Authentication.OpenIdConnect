namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Declares whether token refresh coordination is expected to stay within one process or span multiple application instances.
/// </summary>
public enum TokenCacheDeploymentMode
{
    /// <summary>
    /// Uses the package defaults that are suitable for development and single-instance deployments.
    /// </summary>
    SingleInstance = 0,

    /// <summary>
    /// Requires host-provided cross-node refresh locking and atomic session-state persistence.
    /// </summary>
    MultiInstance = 1
}
