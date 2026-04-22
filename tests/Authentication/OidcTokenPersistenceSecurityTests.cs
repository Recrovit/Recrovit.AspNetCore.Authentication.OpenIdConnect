using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class OidcTokenPersistenceSecurityTests
{
    [Fact]
    public async Task TicketReceived_PersistsTokensOutsideCookieAndClearsAuthenticationProperties()
    {
        var tokenStore = new InMemoryTokenStore();
        using var serviceProvider = CreateServiceProvider(tokenStore);
        var options = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        var properties = CreateAuthenticationProperties(
            (OpenIdConnectParameterNames.AccessToken, "access-1"),
            (OpenIdConnectParameterNames.RefreshToken, "refresh-1"),
            (OpenIdConnectParameterNames.IdToken, "id-1"),
            (OidcAuthenticationConstants.TokenNames.ExpiresAt, "2030-01-01T00:00:00Z"));

        var context = CreateTicketReceivedContext(serviceProvider, properties);

        await options.Events!.TicketReceived(context);

        Assert.NotNull(tokenStore.StoredSessionTokenSet);
        Assert.Equal("refresh-1", tokenStore.StoredSessionTokenSet!.RefreshToken);
        Assert.Equal("id-1", tokenStore.StoredSessionTokenSet.IdToken);
        Assert.Contains(context.Principal!.Claims, claim => claim.Type == OidcAuthenticationConstants.ProviderClaimNames.LocalSessionId);
        Assert.Single(tokenStore.StoredSessionKeys);
        Assert.Empty(properties.GetTokens());
    }

    [Fact]
    public async Task TicketReceived_PersistsSessionTokens_WhenAccessTokenMissing()
    {
        var tokenStore = new InMemoryTokenStore();
        using var serviceProvider = CreateServiceProvider(tokenStore);
        var options = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        var properties = CreateAuthenticationProperties(
            (OpenIdConnectParameterNames.RefreshToken, "refresh-1"),
            (OpenIdConnectParameterNames.IdToken, "id-1"));

        var context = CreateTicketReceivedContext(serviceProvider, properties);

        await options.Events!.TicketReceived(context);

        Assert.NotNull(tokenStore.StoredSessionTokenSet);
        Assert.Equal("refresh-1", tokenStore.StoredSessionTokenSet!.RefreshToken);
        Assert.Empty(tokenStore.ApiTokens);
        Assert.Empty(properties.GetTokens());
    }

    [Fact]
    public async Task TicketReceived_CreatesNewSessionId_WhenMissingFromPrincipal()
    {
        var tokenStore = new InMemoryTokenStore();
        using var serviceProvider = CreateServiceProvider(tokenStore);
        var options = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);
        var properties = CreateAuthenticationProperties((OpenIdConnectParameterNames.RefreshToken, "refresh-1"));
        var context = CreateTicketReceivedContext(serviceProvider, properties, CreateAuthenticatedUser(includeSessionId: false));

        await options.Events!.TicketReceived(context);

        var sessionId = context.Principal!.FindFirst(OidcAuthenticationConstants.ProviderClaimNames.LocalSessionId)?.Value;
        Assert.False(string.IsNullOrWhiteSpace(sessionId));
        Assert.DoesNotContain("session-123", sessionId!, StringComparison.Ordinal);
        Assert.Single(tokenStore.StoredSessionKeys);
        Assert.Contains(sessionId!, tokenStore.StoredSessionKeys[0], StringComparison.Ordinal);
    }

    private static ServiceProvider CreateServiceProvider(InMemoryTokenStore tokenStore)
    {
        var services = new ServiceCollection();
        services.AddOidcAuthenticationInfrastructure(TestConfiguration.Build(), new FakeWebHostEnvironment());
        services.RemoveAll<IDownstreamUserTokenStore>();
        services.AddSingleton<IDownstreamUserTokenStore>(tokenStore);
        return services.BuildServiceProvider();
    }

    private static TicketReceivedContext CreateTicketReceivedContext(
        IServiceProvider serviceProvider,
        AuthenticationProperties properties,
        ClaimsPrincipal? authenticatedUser = null)
    {
        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider,
            User = authenticatedUser ?? CreateAuthenticatedUser()
        };

        var scheme = new AuthenticationScheme(
            OpenIdConnectDefaults.AuthenticationScheme,
            OpenIdConnectDefaults.AuthenticationScheme,
            typeof(RecordingChallengeHandler));
        var ticket = new AuthenticationTicket(httpContext.User, properties, OpenIdConnectDefaults.AuthenticationScheme);
        var options = serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        return new TicketReceivedContext(httpContext, scheme, options, ticket);
    }

    private static ClaimsPrincipal CreateAuthenticatedUser(bool includeSessionId = true)
    {
        if (includeSessionId)
        {
            return TestUsers.CreateAuthenticatedUser([new Claim("sub", "user-123")]);
        }

        return new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "user-123")
        ], "test"));
    }

    private static AuthenticationProperties CreateAuthenticationProperties(params (string Name, string Value)[] tokens)
    {
        var properties = new AuthenticationProperties();
        properties.StoreTokens(tokens.Select(token => new AuthenticationToken
        {
            Name = token.Name,
            Value = token.Value
        }));

        return properties;
    }
}
