using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Stores token sets for authenticated sessions in a protected cache representation.
/// </summary>
public interface IDownstreamUserTokenStore
{
    /// <summary>
    /// Gets the stored OIDC session token set for the specified authenticated session from the encrypted token cache.
    /// </summary>
    /// <param name="user">The authenticated session principal whose token entry should be retrieved.</param>
    /// <param name="cancellationToken">The cancellation token for the asynchronous operation.</param>
    /// <returns>The stored session token set, or <see langword="null"/> when no entry is stored for the authenticated session.</returns>
    Task<StoredOidcSessionTokenSet?> GetSessionTokenSetAsync(ClaimsPrincipal user, CancellationToken cancellationToken);

    /// <summary>
    /// Stores the OIDC session token set for the specified authenticated session in encrypted form.
    /// </summary>
    /// <param name="user">The authenticated session principal whose token entry should be stored.</param>
    /// <param name="tokenSet">The token set to persist for the user.</param>
    /// <param name="cancellationToken">The cancellation token for the asynchronous operation.</param>
    Task StoreSessionTokenSetAsync(ClaimsPrincipal user, StoredOidcSessionTokenSet tokenSet, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the cached downstream API access token for the specified authenticated session and API.
    /// </summary>
    /// <param name="user">The authenticated session principal whose token entry should be retrieved.</param>
    /// <param name="downstreamApiName">The logical downstream API name.</param>
    /// <param name="scopes">The normalized scope list used to request the token.</param>
    /// <param name="cancellationToken">The cancellation token for the asynchronous operation.</param>
    /// <returns>The cached downstream API token, or <see langword="null"/> when no entry is stored.</returns>
    Task<CachedDownstreamApiTokenEntry?> GetApiTokenAsync(
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> scopes,
        CancellationToken cancellationToken);

    /// <summary>
    /// Stores a downstream API access token for the specified authenticated session and API in encrypted form.
    /// </summary>
    /// <param name="user">The authenticated session principal whose token entry should be stored.</param>
    /// <param name="downstreamApiName">The logical downstream API name.</param>
    /// <param name="scopes">The normalized scope list used to request the token.</param>
    /// <param name="tokenEntry">The downstream API access token entry to persist.</param>
    /// <param name="cancellationToken">The cancellation token for the asynchronous operation.</param>
    Task StoreApiTokenAsync(
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> scopes,
        CachedDownstreamApiTokenEntry tokenEntry,
        CancellationToken cancellationToken);

    /// <summary>
    /// Removes the stored encrypted token data for the specified authenticated session.
    /// </summary>
    /// <param name="user">The authenticated session principal whose token entry should be removed.</param>
    /// <param name="cancellationToken">The cancellation token for the asynchronous operation.</param>
    Task RemoveAsync(ClaimsPrincipal user, CancellationToken cancellationToken);
}
