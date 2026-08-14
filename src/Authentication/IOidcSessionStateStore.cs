using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Stores the complete authenticated-session token state as a versioned aggregate.
/// </summary>
public interface IOidcSessionStateStore
{
    /// <summary>
    /// Gets the complete stored token state for the specified authenticated session.
    /// </summary>
    Task<VersionedOidcSessionState?> GetSessionStateAsync(ClaimsPrincipal user, CancellationToken cancellationToken);

    /// <summary>
    /// Attempts to replace the complete stored token state when the stored concurrency version matches the expected value.
    /// </summary>
    /// <remarks>
    /// In <c>MultiInstance</c> deployments, implementations are expected to provide an atomic compare-and-swap operation
    /// across nodes. A read-then-write sequence backed only by best-effort cache semantics is not sufficient.
    /// </remarks>
    Task<bool> TryCompareAndSwapSessionStateAsync(
        ClaimsPrincipal user,
        string? expectedVersion,
        OidcSessionState newState,
        CancellationToken cancellationToken);

    /// <summary>
    /// Deletes the complete stored token state for the specified authenticated session.
    /// </summary>
    Task DeleteSessionStateAsync(ClaimsPrincipal user, CancellationToken cancellationToken);

}
