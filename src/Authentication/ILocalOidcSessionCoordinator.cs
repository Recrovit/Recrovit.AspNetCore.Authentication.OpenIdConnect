using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Coordinates state-changing work for one authenticated local session within the current process.
/// </summary>
/// <remarks>
/// This coordinator does not provide cross-node exclusion and does not replace
/// <see cref="IOidcSessionRefreshLockProvider"/> in multi-instance deployments.
/// </remarks>
public interface ILocalOidcSessionCoordinator
{
    /// <summary>
    /// Acquires the process-local lock for the specified authenticated session.
    /// </summary>
    Task<ILocalOidcSessionLockLease> AcquireAsync(ClaimsPrincipal user, CancellationToken cancellationToken);
}

/// <summary>
/// Represents ownership of a process-local authenticated-session lock.
/// </summary>
public interface ILocalOidcSessionLockLease : IAsyncDisposable
{
}
