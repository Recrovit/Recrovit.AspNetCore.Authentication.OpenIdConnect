using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal interface IUserRefreshLockProvider
{
    ValueTask<IUserRefreshLockLease> AcquireAsync(ClaimsPrincipal user, CancellationToken cancellationToken);
}

internal interface IUserRefreshLockLease : IAsyncDisposable
{
    string OwnerToken { get; }

    DateTimeOffset ExpiresAtUtc { get; }
}
