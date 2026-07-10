using System.ComponentModel.DataAnnotations;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// OpenID Connect provider settings for the host application.
/// </summary>
public sealed class OidcProviderOptions
{
    /// <summary>
    /// Configuration section name.
    /// </summary>
    public const string SectionName = "Providers";

    /// <summary>
    /// Gets the authority URL of the identity provider.
    /// </summary>
    [Required]
    public string Authority { get; init; } = string.Empty;

    /// <summary>
    /// Gets the OIDC client identifier.
    /// </summary>
    [Required]
    public string ClientId { get; init; } = string.Empty;

    /// <summary>
    /// Gets the OIDC client secret.
    /// </summary>
    public string? ClientSecret { get; init; }

    /// <summary>
    /// Gets the client authentication method used when calling the token endpoint.
    /// </summary>
    public OidcClientAuthenticationMethod ClientAuthenticationMethod { get; init; } = OidcClientAuthenticationMethod.ClientSecretPost;

    /// <summary>
    /// Gets the client certificate source settings used for certificate-based client authentication.
    /// </summary>
    public OidcClientCertificateOptions? ClientCertificate { get; init; }

    /// <summary>
    /// Gets the requested scopes.
    /// </summary>
    public string[] Scopes { get; init; } = [];

    /// <summary>
    /// Gets the callback path used after sign-in.
    /// </summary>
    public string CallbackPath { get; init; } = "/signin-oidc";

    /// <summary>
    /// Gets the sign-out callback path.
    /// </summary>
    public string SignedOutCallbackPath { get; init; } = "/signout-callback-oidc";

    /// <summary>
    /// Gets the remote sign-out path.
    /// </summary>
    public string RemoteSignOutPath { get; init; } = "/signout-oidc";

    /// <summary>
    /// Gets the final redirect path after sign-out.
    /// </summary>
    public string SignedOutRedirectPath { get; init; } = "/";

    /// <summary>
    /// Gets a value indicating whether claims should be loaded from UserInfo.
    /// </summary>
    public bool GetClaimsFromUserInfoEndpoint { get; init; } = true;

    /// <summary>
    /// Gets a value indicating whether HTTPS metadata is required.
    /// </summary>
    public bool RequireHttpsMetadata { get; init; } = true;
}
