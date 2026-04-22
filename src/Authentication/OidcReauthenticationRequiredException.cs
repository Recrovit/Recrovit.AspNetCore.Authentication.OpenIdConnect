namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// The exception that is thrown when the current authenticated session can no longer produce a usable downstream access token.
/// </summary>
public sealed class OidcReauthenticationRequiredException : InvalidOperationException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="OidcReauthenticationRequiredException"/> class.
    /// </summary>
    /// <param name="message">The exception message.</param>
    public OidcReauthenticationRequiredException(string message) : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcReauthenticationRequiredException"/> class.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <param name="innerException">The exception that caused the current exception.</param>
    public OidcReauthenticationRequiredException(string message, Exception innerException) : base(message, innerException) { }
}
