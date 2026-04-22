using System.Security.Claims;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal sealed class UserRefreshLockProvider(IOptions<ActiveOidcProviderOptions> activeProviderOptions) : IUserRefreshLockProvider
{
    private readonly object syncRoot = new();
    private readonly Dictionary<string, LockEntry> entries = new(StringComparer.Ordinal);
    private readonly UserTokenCacheKeyContextAccessor cacheKeyContextAccessor = new(activeProviderOptions);

    public async ValueTask<IAsyncDisposable> AcquireAsync(ClaimsPrincipal user, string downstreamApiName, CancellationToken cancellationToken)
    {
        var context = cacheKeyContextAccessor.GetRequiredContext(user);
        var userKey = $"{context.Provider}:{context.Issuer}:{context.SubjectId}:{context.SessionId}:{downstreamApiName}";
        LockEntry? entry;

        lock (syncRoot)
        {
            if (!entries.TryGetValue(userKey, out entry))
            {
                entry = new LockEntry();
                entries[userKey] = entry;
            }

            entry.LeaseCount++;
        }

        ArgumentNullException.ThrowIfNull(entry);
        await entry.Semaphore.WaitAsync(cancellationToken);
        return new Releaser(this, userKey, entry);
    }

    private void Release(string userKey, LockEntry entry)
    {
        entry.Semaphore.Release();

        lock (syncRoot)
        {
            entry.LeaseCount--;
            if (entry.LeaseCount == 0 &&
                entries.TryGetValue(userKey, out var currentEntry) &&
                ReferenceEquals(currentEntry, entry))
            {
                entries.Remove(userKey);
            }
        }
    }

    private sealed class LockEntry
    {
        public SemaphoreSlim Semaphore { get; } = new(1, 1);

        public int LeaseCount { get; set; }
    }

    private sealed class Releaser(UserRefreshLockProvider owner, string userKey, LockEntry entry) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            owner.Release(userKey, entry);
            return ValueTask.CompletedTask;
        }
    }
}
