using Microsoft.Extensions.DependencyInjection;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class LocalOidcSessionCoordinatorTests
{
    [Fact]
    public async Task AcquireAsync_SerializesSameSessionAcrossScopes()
    {
        using var serviceProvider = CreateServiceProvider();
        using var firstScope = serviceProvider.CreateScope();
        using var secondScope = serviceProvider.CreateScope();
        var firstCoordinator = firstScope.ServiceProvider.GetRequiredService<ILocalOidcSessionCoordinator>();
        var secondCoordinator = secondScope.ServiceProvider.GetRequiredService<ILocalOidcSessionCoordinator>();
        var user = TestUsers.CreateAuthenticatedUser();

        await using var firstLease = await firstCoordinator.AcquireAsync(user, TestContext.Current.CancellationToken);
        var secondAcquire = secondCoordinator.AcquireAsync(user, TestContext.Current.CancellationToken);

        await Task.Delay(50, TestContext.Current.CancellationToken);
        Assert.False(secondAcquire.IsCompleted);

        await firstLease.DisposeAsync();
        await using var secondLease = await secondAcquire;
    }

    [Fact]
    public async Task AcquireAsync_DoesNotBlockDifferentSessions()
    {
        using var serviceProvider = CreateServiceProvider();
        var coordinator = serviceProvider.GetRequiredService<ILocalOidcSessionCoordinator>();

        await using var firstLease = await coordinator.AcquireAsync(
            TestUsers.CreateAuthenticatedUser(sessionId: "session-a"),
            TestContext.Current.CancellationToken);
        var secondAcquire = coordinator.AcquireAsync(
            TestUsers.CreateAuthenticatedUser(sessionId: "session-b"),
            TestContext.Current.CancellationToken);

        await using var secondLease = await secondAcquire.WaitAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task AcquireAsync_RemovesCanceledWaiterWithoutLosingCurrentOwner()
    {
        using var serviceProvider = CreateServiceProvider();
        var coordinator = serviceProvider.GetRequiredService<ILocalOidcSessionCoordinator>();
        var user = TestUsers.CreateAuthenticatedUser();

        await using var firstLease = await coordinator.AcquireAsync(user, TestContext.Current.CancellationToken);
        using var cancellation = new CancellationTokenSource();
        var canceledAcquire = coordinator.AcquireAsync(user, cancellation.Token);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => canceledAcquire);

        var nextAcquire = coordinator.AcquireAsync(user, TestContext.Current.CancellationToken);
        await Task.Delay(50, TestContext.Current.CancellationToken);
        Assert.False(nextAcquire.IsCompleted);

        await firstLease.DisposeAsync();
        await using var nextLease = await nextAcquire;
    }

    private static ServiceProvider CreateServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOidcAuthenticationInfrastructure(TestConfiguration.Build(), new FakeWebHostEnvironment());
        return services.BuildServiceProvider();
    }
}
