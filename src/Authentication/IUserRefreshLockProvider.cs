using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal interface IUserRefreshLockProvider
{
    ValueTask<IAsyncDisposable> AcquireAsync(ClaimsPrincipal user, string downstreamApiName, CancellationToken cancellationToken);
}
