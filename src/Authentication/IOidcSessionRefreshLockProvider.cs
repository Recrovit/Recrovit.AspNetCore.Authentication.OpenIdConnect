using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Coordinates downstream token refresh work for one authenticated local session.
/// </summary>
public interface IOidcSessionRefreshLockProvider
{
    /// <summary>
    /// Acquires the refresh lease for the specified authenticated session.
    /// </summary>
    /// <remarks>
    /// In <c>MultiInstance</c> deployments, implementations are expected to provide session-scoped exclusion across nodes
    /// for the whole lease duration and to return stable lease metadata that can be revalidated before persisting refresh results.
    /// </remarks>
    Task<IOidcSessionRefreshLockLease> AcquireAsync(ClaimsPrincipal user, CancellationToken cancellationToken);
}

/// <summary>
/// Represents an acquired session-scoped refresh lease.
/// </summary>
public interface IOidcSessionRefreshLockLease : IAsyncDisposable
{
    /// <summary>
    /// Gets the stable identifier of the current lease owner.
    /// </summary>
    string OwnerToken { get; }

    /// <summary>
    /// Gets when the current lease stops being valid.
    /// </summary>
    DateTimeOffset ExpiresAtUtc { get; }
}
