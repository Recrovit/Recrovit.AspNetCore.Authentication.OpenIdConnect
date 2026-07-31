using System.Security.Claims;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal sealed class LocalOidcSessionCoordinator(
    IOptions<ActiveOidcProviderOptions> activeProviderOptions) : ILocalOidcSessionCoordinator
{
    private readonly object syncRoot = new();
    private readonly Dictionary<string, LockEntry> entries = new(StringComparer.Ordinal);
    private readonly UserTokenCacheKeyContextAccessor cacheKeyContextAccessor = new(activeProviderOptions);

    public async Task<ILocalOidcSessionLockLease> AcquireAsync(
        ClaimsPrincipal user,
        CancellationToken cancellationToken)
    {
        var sessionKey = CreateSessionKey(cacheKeyContextAccessor.GetRequiredContext(user));
        LockEntry entry;
        lock (syncRoot)
        {
            if (!entries.TryGetValue(sessionKey, out entry!))
            {
                entry = new LockEntry();
                entries[sessionKey] = entry;
            }

            entry.LeaseCount++;
        }

        try
        {
            await entry.Semaphore.WaitAsync(cancellationToken);
        }
        catch
        {
            RemoveLeaseReference(sessionKey, entry);
            throw;
        }

        return new Lease(this, sessionKey, entry);
    }

    private static string CreateSessionKey(UserTokenCacheKeyContext context)
        => $"{context.Provider}\n{context.Issuer}\n{context.SubjectId}\n{context.SessionId}";

    private void Release(string sessionKey, LockEntry entry)
    {
        entry.Semaphore.Release();
        RemoveLeaseReference(sessionKey, entry);
    }

    private void RemoveLeaseReference(string sessionKey, LockEntry entry)
    {
        lock (syncRoot)
        {
            entry.LeaseCount--;
            if (entry.LeaseCount == 0 &&
                entries.TryGetValue(sessionKey, out var currentEntry) &&
                ReferenceEquals(currentEntry, entry))
            {
                entries.Remove(sessionKey);
            }
        }
    }

    private sealed class LockEntry
    {
        public SemaphoreSlim Semaphore { get; } = new(1, 1);

        public int LeaseCount { get; set; }
    }

    private sealed class Lease(
        LocalOidcSessionCoordinator owner,
        string sessionKey,
        LockEntry entry) : ILocalOidcSessionLockLease
    {
        private int released;

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref released, 1) == 0)
            {
                owner.Release(sessionKey, entry);
            }

            return ValueTask.CompletedTask;
        }
    }
}

internal static class LocalOidcSessionCoordinatorRegistry
{
    private static readonly object SyncRoot = new();
    private static readonly Dictionary<string, ILocalOidcSessionCoordinator> Coordinators = new(StringComparer.Ordinal);

    public static ILocalOidcSessionCoordinator GetOrCreate(IOptions<ActiveOidcProviderOptions> activeProviderOptions)
    {
        var providerName = activeProviderOptions.Value.ProviderName;
        lock (SyncRoot)
        {
            if (!Coordinators.TryGetValue(providerName, out var coordinator))
            {
                coordinator = new LocalOidcSessionCoordinator(
                    Options.Create(new ActiveOidcProviderOptions { ProviderName = providerName }));
                Coordinators[providerName] = coordinator;
            }

            return coordinator;
        }
    }
}
