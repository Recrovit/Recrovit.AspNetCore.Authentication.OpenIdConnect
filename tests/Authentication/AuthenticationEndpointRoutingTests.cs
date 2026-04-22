using System.Net;
using System.Security.Claims;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class AuthenticationEndpointRoutingTests
{
    [Fact]
    public async Task LogoutEndpoint_ReturnsMethodNotAllowed_ForGetRequests()
    {
        await using var app = await CreateApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/authentication/logout", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    [Fact]
    public async Task LogoutEndpoint_RejectsPostWithoutAntiforgeryToken()
    {
        await using var app = await CreateApplicationAsync();
        using var client = app.GetTestClient();

        using var response = await client.PostAsync(
            "/authentication/logout",
            new FormUrlEncodedContent([]),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task PrincipalEndpoint_ReturnsMinimalPrincipalPayload()
    {
        await using var app = await CreateApplicationAsync(authenticatedUser: TestUsers.CreateAuthenticatedUser(
            [
                new(JwtRegisteredClaimNames.Sub, "user-123", System.Security.Claims.ClaimValueTypes.String, "https://idp.example.com"),
                new(JwtRegisteredClaimNames.Iss, "https://issuer.example.com"),
                new(OidcAuthenticationConstants.ProviderClaimNames.ObjectId, "object-456"),
                new(JwtRegisteredClaimNames.PreferredUsername, "ada")
            ]));
        using var client = app.GetTestClient();

        using var response = await client.GetAsync("/authentication/principal", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var payload = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))?.AsObject();
        Assert.NotNull(payload);
        Assert.Equal(7, payload.Count);
        Assert.True(payload["isAuthenticated"]?.GetValue<bool>());
        Assert.Equal("user-123", payload["name"]?.GetValue<string>());
        Assert.Equal("ada", payload["preferredUsername"]?.GetValue<string>());
        Assert.True(payload["email"] is null || payload["email"]!.GetValue<string?>() is null);
        Assert.Equal("user-123", payload["subjectId"]?.GetValue<string>());
        Assert.Equal("https://issuer.example.com", payload["issuer"]?.GetValue<string>());
        Assert.Equal("object-456", payload["objectId"]?.GetValue<string>());
        Assert.False(payload.ContainsKey("identities"));
        Assert.False(payload.ContainsKey("claims"));
    }

    private static async Task<WebApplication> CreateApplicationAsync(System.Security.Claims.ClaimsPrincipal? authenticatedUser = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = Environments.Development
        });

        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(TestConfiguration.CreateBaseConfiguration());
        builder.AddRecrovitOpenIdConnectInfrastructure();
        builder.Services.Replace(ServiceDescriptor.Scoped<IDownstreamUserTokenStore>(_ => new InMemoryTokenStore(
            authenticatedUser ?? TestUsers.CreateAuthenticatedUser(),
            CreateStoredTokenEntry(authenticatedUser))));
        builder.Services.Replace(ServiceDescriptor.Scoped<IDownstreamUserTokenProvider, StubDownstreamUserTokenProvider>());

        var app = builder.Build();
        if (authenticatedUser is not null)
        {
            app.Use((httpContext, next) =>
            {
                httpContext.User = authenticatedUser;
                return next(httpContext);
            });
        }

        app.UseRecrovitOpenIdConnectAuthentication();
        app.MapOidcAuthenticationEndpoints();

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static StoredOidcSessionTokenSet? CreateStoredTokenEntry(ClaimsPrincipal? authenticatedUser)
    {
        var subjectId = authenticatedUser?.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
            ?? authenticatedUser?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        return string.IsNullOrWhiteSpace(subjectId)
            ? null
            : new StoredOidcSessionTokenSet
            {
                RefreshToken = "refresh-token",
                ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(5)
            };
    }
}
