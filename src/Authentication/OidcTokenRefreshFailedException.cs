namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// The exception that is thrown when the token refresh flow fails due to server-side, transport, or configuration issues
/// and the current session should not be invalidated automatically.
/// </summary>
public sealed class OidcTokenRefreshFailedException : InvalidOperationException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="OidcTokenRefreshFailedException"/> class.
    /// </summary>
    /// <param name="message">The exception message.</param>
    public OidcTokenRefreshFailedException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcTokenRefreshFailedException"/> class.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <param name="innerException">The exception that caused the current exception.</param>
    public OidcTokenRefreshFailedException(string message, Exception innerException) : base(message, innerException) { }
}
