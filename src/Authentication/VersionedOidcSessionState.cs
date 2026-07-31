namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Wraps a stored session token aggregate together with its concurrency version.
/// </summary>
public sealed class VersionedOidcSessionState
{
    /// <summary>
    /// Initializes a new instance of the <see cref="VersionedOidcSessionState"/> class.
    /// </summary>
    public VersionedOidcSessionState(string version, OidcSessionState state)
    {
        Version = version;
        State = state;
    }

    /// <summary>
    /// Gets the current concurrency version.
    /// </summary>
    public string Version { get; }

    /// <summary>
    /// Gets the stored token state payload.
    /// </summary>
    public OidcSessionState State { get; }
}
