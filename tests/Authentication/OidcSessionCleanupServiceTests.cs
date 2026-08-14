using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using System.Security.Claims;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class OidcSessionCleanupServiceTests
{
    [Fact]
    public async Task ClearSessionAsync_WaitsForOngoingTokenSave_AndSignsOutAfterRemovingTokens()
    {
        var user = TestUsers.CreateAuthenticatedUser();
        var signOutRecorder = new SignOutRecorder();
        CoordinatedBlockingTokenStore? tokenStore = null;
        var serviceProvider = CreateServiceProvider(user, signOutRecorder, store =>
        {
            tokenStore = store;
        });
        tokenStore ??= (CoordinatedBlockingTokenStore)serviceProvider.GetRequiredService<IDownstreamUserTokenStore>();
        var cleanupServiceType = typeof(AuthenticationEndpoints).Assembly.GetType(
            "Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication.OidcSessionCleanupService")
            ?? throw new InvalidOperationException("The OIDC session cleanup service type could not be resolved.");
        var cleanupService = ActivatorUtilities.CreateInstance(serviceProvider, cleanupServiceType);

        await tokenStore.StoreSessionTokenSetAsync(user, new StoredOidcSessionTokenSet
        {
            RefreshToken = "refresh-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, TestContext.Current.CancellationToken);

        var save = tokenStore.StoreApiTokenAsync(user, "SessionValidationApi", ["openid"], new CachedDownstreamApiTokenEntry
        {
            AccessToken = "access-token",
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
        }, TestContext.Current.CancellationToken);
        await tokenStore.SaveStarted;

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider,
            User = user
        };

        var cleanup = (Task)(cleanupServiceType.GetMethod("ClearSessionAsync")
            ?? throw new InvalidOperationException("The ClearSessionAsync method could not be resolved."))
            .Invoke(cleanupService, [httpContext, "test-cleanup", null])!;
        await Task.Delay(50, TestContext.Current.CancellationToken);

        Assert.False(cleanup.IsCompleted);

        tokenStore.ReleaseSave();

        await save;
        await cleanup;

        Assert.True(tokenStore.Inner.RemoveCalled);
        Assert.Null(await tokenStore.Inner.GetSessionStateAsync(user, TestContext.Current.CancellationToken));

        var signOutCall = Assert.Single(signOutRecorder.Calls);
        Assert.Equal(CookieAuthenticationDefaults.AuthenticationScheme, signOutCall.Scheme);
        Assert.NotNull(tokenStore.Inner.RemoveSequence);
        Assert.True(tokenStore.Inner.RemoveSequence < signOutCall.Sequence);
    }

    private static ServiceProvider CreateServiceProvider(
        ClaimsPrincipal user,
        SignOutRecorder signOutRecorder,
        Action<CoordinatedBlockingTokenStore> captureStore)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOidcAuthenticationInfrastructure(TestConfiguration.Build(), new FakeWebHostEnvironment());
        services.AddSingleton(signOutRecorder);
        services.AddSingleton<ChallengeRecorder>();
        services.AddSingleton<IAuthenticationService, RecordingAuthenticationService>();
        services.AddSingleton<IDownstreamUserTokenStore>(serviceProvider =>
        {
            var store = new CoordinatedBlockingTokenStore(
                serviceProvider.GetRequiredService<ILocalOidcSessionCoordinator>(),
                user);
            captureStore(store);
            return store;
        });
        return services.BuildServiceProvider();
    }

    private sealed class CoordinatedBlockingTokenStore(
        ILocalOidcSessionCoordinator coordinator,
        ClaimsPrincipal initialUser) : IDownstreamUserTokenStore
    {
        private readonly TaskCompletionSource saveStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource releaseSave = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public InMemoryTokenStore Inner { get; } = new(initialUser);

        public Task SaveStarted => saveStarted.Task;

        public void ReleaseSave() => releaseSave.TrySetResult();

        public Task<StoredOidcSessionTokenSet?> GetSessionTokenSetAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
            => Inner.GetSessionTokenSetAsync(user, cancellationToken);

        public Task StoreSessionTokenSetAsync(ClaimsPrincipal user, StoredOidcSessionTokenSet tokenSet, CancellationToken cancellationToken)
            => Inner.StoreSessionTokenSetAsync(user, tokenSet, cancellationToken);

        public Task StoreSessionTokenSetAsync(
            ClaimsPrincipal user,
            StoredOidcSessionTokenSet tokenSet,
            ILocalOidcSessionLockLease localSessionLock,
            CancellationToken cancellationToken)
            => Inner.StoreSessionTokenSetAsync(user, tokenSet, cancellationToken);

        public Task<CachedDownstreamApiTokenEntry?> GetApiTokenAsync(
            ClaimsPrincipal user,
            string downstreamApiName,
            IReadOnlyCollection<string> scopes,
            CancellationToken cancellationToken)
            => Inner.GetApiTokenAsync(user, downstreamApiName, scopes, cancellationToken);

        public async Task StoreApiTokenAsync(
            ClaimsPrincipal user,
            string downstreamApiName,
            IReadOnlyCollection<string> scopes,
            CachedDownstreamApiTokenEntry tokenEntry,
            CancellationToken cancellationToken)
        {
            await using var localSessionLock = await coordinator.AcquireAsync(user, cancellationToken);
            saveStarted.TrySetResult();
            await releaseSave.Task.WaitAsync(cancellationToken);
            await Inner.StoreApiTokenAsync(user, downstreamApiName, scopes, tokenEntry, cancellationToken);
        }

        public Task StoreApiTokenAsync(
            ClaimsPrincipal user,
            string downstreamApiName,
            IReadOnlyCollection<string> scopes,
            CachedDownstreamApiTokenEntry tokenEntry,
            ILocalOidcSessionLockLease localSessionLock,
            CancellationToken cancellationToken)
            => Inner.StoreApiTokenAsync(user, downstreamApiName, scopes, tokenEntry, cancellationToken);

        public Task RemoveAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
            => Inner.RemoveAsync(user, cancellationToken);

        public Task RemoveAsync(
            ClaimsPrincipal user,
            ILocalOidcSessionLockLease localSessionLock,
            CancellationToken cancellationToken)
            => Inner.RemoveAsync(user, cancellationToken);
    }
}
