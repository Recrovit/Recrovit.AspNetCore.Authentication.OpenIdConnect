using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Provides downstream API access tokens for the authenticated user.
/// </summary>
public interface IDownstreamUserTokenProvider
{
    /// <summary>
    /// Gets an access token for the requested downstream API.
    /// </summary>
    /// <param name="user">The authenticated user for whom the access token should be resolved.</param>
    /// <param name="downstreamApiName">The logical name of the downstream API.</param>
    /// <param name="cancellationToken">The cancellation token for the asynchronous operation.</param>
    /// <returns>The access token to use for the downstream API call.</returns>
    Task<string> GetAccessTokenAsync(ClaimsPrincipal user, string downstreamApiName, CancellationToken cancellationToken);
}
