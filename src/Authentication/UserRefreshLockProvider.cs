using System.Security.Claims;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal sealed class UserRefreshLockProvider(
    IOptions<ActiveOidcProviderOptions> activeProviderOptions) : IOidcSessionRefreshLockProvider
{
    private readonly object syncRoot = new();
    private readonly Dictionary<string, LockEntry> entries = new(StringComparer.Ordinal);
    private readonly UserTokenCacheKeyContextAccessor cacheKeyContextAccessor = new(activeProviderOptions);

    public async Task<IOidcSessionRefreshLockLease> AcquireAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        var userKey = cacheKeyContextAccessor.GetRequiredContext(user).CreateSessionKey();
        LockEntry entry;
        lock (syncRoot)
        {
            if (!entries.TryGetValue(userKey, out entry!))
            {
                entry = new LockEntry();
                entries[userKey] = entry;
            }

            entry.LeaseCount++;
        }

        try
        {
            await entry.Semaphore.WaitAsync(cancellationToken);
        }
        catch
        {
            RemoveLeaseReference(userKey, entry);
            throw;
        }

        return new Releaser(
            this,
            userKey,
            entry,
            Guid.NewGuid().ToString("n"),
            DateTimeOffset.MaxValue);
    }

    private void Release(string userKey, LockEntry entry)
    {
        entry.Semaphore.Release();
        RemoveLeaseReference(userKey, entry);
    }

    private void RemoveLeaseReference(string userKey, LockEntry entry)
    {
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

    private sealed class Releaser(
        UserRefreshLockProvider owner,
        string userKey,
        LockEntry entry,
        string ownerToken,
        DateTimeOffset expiresAtUtc) : IOidcSessionRefreshLockLease
    {
        public string OwnerToken { get; } = ownerToken;

        public DateTimeOffset ExpiresAtUtc { get; } = expiresAtUtc;

        private int released;

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref released, 1) == 0)
            {
                owner.Release(userKey, entry);
            }

            return ValueTask.CompletedTask;
        }
    }
}
