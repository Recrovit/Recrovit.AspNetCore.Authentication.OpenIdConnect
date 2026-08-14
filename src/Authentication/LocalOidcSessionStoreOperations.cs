using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal static class LocalOidcSessionStoreOperations
{
    public static Task<VersionedOidcSessionState?> GetSessionStateAsync(
        IOidcSessionStateStore sessionStateStore,
        ClaimsPrincipal user,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
        => sessionStateStore is DistributedDownstreamUserTokenStore builtInStore
            ? builtInStore.GetSessionStateAsync(user, localSessionLock, cancellationToken)
            : sessionStateStore.GetSessionStateAsync(user, cancellationToken);

    public static Task<bool> TryCompareAndSwapSessionStateAsync(
        IOidcSessionStateStore sessionStateStore,
        ClaimsPrincipal user,
        string? expectedVersion,
        OidcSessionState newState,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
        => sessionStateStore is DistributedDownstreamUserTokenStore builtInStore
            ? builtInStore.TryCompareAndSwapSessionStateAsync(user, expectedVersion, newState, localSessionLock, cancellationToken)
            : sessionStateStore.TryCompareAndSwapSessionStateAsync(user, expectedVersion, newState, cancellationToken);

    public static Task DeleteSessionStateAsync(
        IOidcSessionStateStore sessionStateStore,
        ClaimsPrincipal user,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
    {
        return sessionStateStore is DistributedDownstreamUserTokenStore builtInStore
            ? builtInStore.DeleteSessionStateAsync(user, localSessionLock, cancellationToken)
            : sessionStateStore.DeleteSessionStateAsync(user, cancellationToken);
    }

    public static Task StoreSessionTokenSetAsync(
        IDownstreamUserTokenStore tokenStore,
        ClaimsPrincipal user,
        StoredOidcSessionTokenSet tokenSet,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
        => tokenStore is DistributedDownstreamUserTokenStore builtInStore
            ? builtInStore.StoreSessionTokenSetAsync(user, tokenSet, localSessionLock, cancellationToken)
            : tokenStore.StoreSessionTokenSetAsync(user, tokenSet, cancellationToken);

    public static Task StoreApiTokenAsync(
        IDownstreamUserTokenStore tokenStore,
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> scopes,
        CachedDownstreamApiTokenEntry tokenEntry,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
        => tokenStore is DistributedDownstreamUserTokenStore builtInStore
            ? builtInStore.StoreApiTokenAsync(user, downstreamApiName, scopes, tokenEntry, localSessionLock, cancellationToken)
            : tokenStore.StoreApiTokenAsync(user, downstreamApiName, scopes, tokenEntry, cancellationToken);

    public static Task RemoveAsync(
        IDownstreamUserTokenStore tokenStore,
        ClaimsPrincipal user,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
        => tokenStore is DistributedDownstreamUserTokenStore builtInStore
            ? builtInStore.RemoveAsync(user, localSessionLock, cancellationToken)
            : tokenStore.RemoveAsync(user, cancellationToken);
}
