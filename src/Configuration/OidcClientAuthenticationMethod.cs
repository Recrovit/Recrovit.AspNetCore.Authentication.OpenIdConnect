namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Supported client authentication methods for token endpoint calls.
/// </summary>
public enum OidcClientAuthenticationMethod
{
    /// <summary>
    /// Sends the client secret in the request body.
    /// </summary>
    ClientSecretPost = 0,

    /// <summary>
    /// Sends a signed client assertion using the private_key_jwt method.
    /// </summary>
    PrivateKeyJwt = 1
}
