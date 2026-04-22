namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Provides shared protocol-related constants used by the OIDC authentication infrastructure.
/// </summary>
public static class OidcAuthenticationConstants
{
    /// <summary>
    /// Provides provider-specific claim names that are not covered by public JWT/OIDC constants.
    /// </summary>
    public static class ProviderClaimNames
    {
        /// <summary>
        /// The Entra/Azure AD object identifier claim name.
        /// </summary>
        public const string ObjectId = "oid";

        /// <summary>
        /// The internal claim name that stores the local authenticated session identifier.
        /// </summary>
        public const string LocalSessionId = "local_session_id";

        /// <summary>
        /// The internal claim name that stores the UTC timestamp when the local session was created.
        /// </summary>
        public const string SessionIssuedAtUtc = "session_issued_at_utc";

        /// <summary>
        /// The internal claim name that stores the UTC timestamp when the local session must expire absolutely.
        /// </summary>
        public const string SessionAbsoluteExpiresAtUtc = "session_absolute_expires_at_utc";
    }

    /// <summary>
    /// Provides token and response field name constants that are not exposed by framework constants.
    /// </summary>
    public static class TokenNames
    {
        /// <summary>
        /// The authentication property key that stores the token expiry timestamp.
        /// </summary>
        public const string ExpiresAt = "expires_at";

        /// <summary>
        /// The JSON field name that stores the token lifetime in seconds.
        /// </summary>
        public const string ExpiresIn = "expires_in";

        /// <summary>
        /// The JSON field name that stores the OAuth error code.
        /// </summary>
        public const string Error = "error";

        /// <summary>
        /// The JWT claim name that stores delegated scopes.
        /// </summary>
        public const string Scope = "scope";

        /// <summary>
        /// The JWT claim name that stores delegated scopes in short form.
        /// </summary>
        public const string Scp = "scp";
    }

    /// <summary>
    /// Provides request classification constants.
    /// </summary>
    public static class RequestPaths
    {
        /// <summary>
        /// The conventional prefix used for API endpoints.
        /// </summary>
        public const string ApiPrefix = "/api";
    }

    /// <summary>
    /// Provides media type constants.
    /// </summary>
    public static class MediaTypes
    {
        /// <summary>
        /// The JSON media type.
        /// </summary>
        public const string Json = "application/json";

        /// <summary>
        /// The structured syntax suffix used by JSON-based media types.
        /// </summary>
        public const string JsonStructuredSyntaxSuffix = "+json";
    }

    /// <summary>
    /// Provides response header constants used by the authentication infrastructure.
    /// </summary>
    public static class ResponseHeaders
    {
        /// <summary>
        /// The response header name written when reauthentication is required.
        /// </summary>
        public const string ReauthenticationRequired = "X-Recrovit-Auth";

        /// <summary>
        /// The response header value written when reauthentication is required.
        /// </summary>
        public const string ReauthenticationRequiredValue = "reauth-required";
    }

    /// <summary>
    /// Provides OAuth error code constants.
    /// </summary>
    public static class OAuthErrors
    {
        /// <summary>
        /// The OAuth error code returned when the refresh grant is no longer valid.
        /// </summary>
        public const string InvalidGrant = "invalid_grant";
    }
}
