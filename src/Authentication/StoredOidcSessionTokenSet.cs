using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Session token set extracted from the OIDC sign-in flow and stored outside the auth cookie.
/// </summary>
public sealed class StoredOidcSessionTokenSet
{
    /// <summary>
    /// Gets the refresh token.
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>
    /// Gets the ID token.
    /// </summary>
    public string? IdToken { get; init; }

    /// <summary>
    /// Gets the session token expiry in UTC.
    /// </summary>
    public DateTimeOffset ExpiresAtUtc { get; init; }

    /// <summary>
    /// Creates a stored session token set from OIDC authentication properties.
    /// </summary>
    /// <param name="properties">The authentication properties containing the tokens returned by the identity provider.</param>
    /// <returns>A stored session token set initialized from the authentication properties.</returns>
    public static StoredOidcSessionTokenSet FromAuthenticationProperties(AuthenticationProperties properties)
    {
        var tokens = properties.GetTokens().ToDictionary(token => token.Name!, token => token.Value, StringComparer.Ordinal);

        var expiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5);
        if (tokens.TryGetValue(OidcAuthenticationConstants.TokenNames.ExpiresAt, out var expiresAtRaw) &&
            DateTimeOffset.TryParse(expiresAtRaw, out var parsedExpiresAt))
        {
            expiresAtUtc = parsedExpiresAt.ToUniversalTime();
        }

        tokens.TryGetValue(OpenIdConnectParameterNames.RefreshToken, out var refreshToken);
        tokens.TryGetValue(OpenIdConnectParameterNames.IdToken, out var idToken);

        return new StoredOidcSessionTokenSet
        {
            RefreshToken = refreshToken,
            IdToken = idToken,
            ExpiresAtUtc = expiresAtUtc
        };
    }
}
