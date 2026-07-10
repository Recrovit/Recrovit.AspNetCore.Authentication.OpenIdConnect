using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Net;
using System.Diagnostics;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.JsonWebTokens;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Provides downstream access tokens using OIDC sign-in and refresh tokens.
/// </summary>
public sealed class OidcDownstreamUserTokenProvider : IDownstreamUserTokenProvider
{
    private readonly IDownstreamUserTokenStore tokenStore;
    private readonly IUserRefreshLockProvider refreshLockProvider;
    private readonly DownstreamApiCatalog downstreamApiCatalog;
    private readonly OidcScopeResolver scopeResolver;
    private readonly IOptions<OidcProviderOptions> oidcOptions;
    private readonly IOptions<ActiveOidcProviderOptions> activeProviderOptions;
    private readonly IOptions<TokenCacheOptions> tokenCacheOptions;
    private readonly ILogger<OidcDownstreamUserTokenProvider> logger;
    private readonly IHttpClientFactory httpClientFactory;
    private readonly IOptionsMonitor<OpenIdConnectOptions> openIdConnectOptionsMonitor;
    private readonly IHostEnvironment hostEnvironment;
    private readonly IOidcClientAssertionService? clientAssertionService;

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcDownstreamUserTokenProvider"/> class.
    /// </summary>
    /// <remarks>
    /// This overload supports <see cref="OidcClientAuthenticationMethod.ClientSecretPost"/>.
    /// When <see cref="OidcClientAuthenticationMethod.PrivateKeyJwt"/> is configured, use the overload
    /// that accepts an <see cref="IOidcClientAssertionService"/> so the refresh token exchange can create
    /// a client assertion.
    /// </remarks>
    public OidcDownstreamUserTokenProvider(
        IDownstreamUserTokenStore tokenStore,
        DownstreamApiCatalog downstreamApiCatalog,
        IOptions<OidcProviderOptions> oidcOptions,
        IOptions<ActiveOidcProviderOptions> activeProviderOptions,
        IOptions<TokenCacheOptions> tokenCacheOptions,
        ILogger<OidcDownstreamUserTokenProvider> logger,
        IHttpClientFactory httpClientFactory,
        IHostEnvironment hostEnvironment,
        IOptionsMonitor<OpenIdConnectOptions> openIdConnectOptionsMonitor)
        : this(
            tokenStore,
            new UserRefreshLockProvider(activeProviderOptions),
            downstreamApiCatalog,
            new OidcScopeResolver(oidcOptions.Value.Scopes, downstreamApiCatalog),
            oidcOptions,
            activeProviderOptions,
            tokenCacheOptions,
            logger,
            httpClientFactory,
            hostEnvironment,
            openIdConnectOptionsMonitor,
            clientAssertionService: null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcDownstreamUserTokenProvider"/> class.
    /// </summary>
    /// <remarks>
    /// Provide <paramref name="clientAssertionService"/> when
    /// <see cref="OidcProviderOptions.ClientAuthenticationMethod"/> is
    /// <see cref="OidcClientAuthenticationMethod.PrivateKeyJwt"/>. For
    /// <see cref="OidcClientAuthenticationMethod.ClientSecretPost"/>, this parameter is optional.
    /// </remarks>
    public OidcDownstreamUserTokenProvider(
        IDownstreamUserTokenStore tokenStore,
        DownstreamApiCatalog downstreamApiCatalog,
        IOptions<OidcProviderOptions> oidcOptions,
        IOptions<ActiveOidcProviderOptions> activeProviderOptions,
        IOptions<TokenCacheOptions> tokenCacheOptions,
        ILogger<OidcDownstreamUserTokenProvider> logger,
        IHttpClientFactory httpClientFactory,
        IHostEnvironment hostEnvironment,
        IOptionsMonitor<OpenIdConnectOptions> openIdConnectOptionsMonitor,
        IOidcClientAssertionService? clientAssertionService)
        : this(
            tokenStore,
            new UserRefreshLockProvider(activeProviderOptions),
            downstreamApiCatalog,
            new OidcScopeResolver(oidcOptions.Value.Scopes, downstreamApiCatalog),
            oidcOptions,
            activeProviderOptions,
            tokenCacheOptions,
            logger,
            httpClientFactory,
            hostEnvironment,
            openIdConnectOptionsMonitor,
            clientAssertionService)
    {
    }

    internal OidcDownstreamUserTokenProvider(
        IDownstreamUserTokenStore tokenStore,
        IUserRefreshLockProvider refreshLockProvider,
        DownstreamApiCatalog downstreamApiCatalog,
        OidcScopeResolver scopeResolver,
        IOptions<OidcProviderOptions> oidcOptions,
        IOptions<ActiveOidcProviderOptions> activeProviderOptions,
        IOptions<TokenCacheOptions> tokenCacheOptions,
        ILogger<OidcDownstreamUserTokenProvider> logger,
        IHttpClientFactory httpClientFactory,
        IHostEnvironment hostEnvironment,
        IOptionsMonitor<OpenIdConnectOptions> openIdConnectOptionsMonitor,
        IOidcClientAssertionService? clientAssertionService)
    {
        this.tokenStore = tokenStore;
        this.refreshLockProvider = refreshLockProvider;
        this.downstreamApiCatalog = downstreamApiCatalog;
        this.scopeResolver = scopeResolver;
        this.oidcOptions = oidcOptions;
        this.activeProviderOptions = activeProviderOptions;
        this.tokenCacheOptions = tokenCacheOptions;
        this.logger = logger;
        this.httpClientFactory = httpClientFactory;
        this.hostEnvironment = hostEnvironment;
        this.openIdConnectOptionsMonitor = openIdConnectOptionsMonitor;
        this.clientAssertionService = clientAssertionService;
    }

    /// <inheritdoc />
    public async Task<string> GetAccessTokenAsync(ClaimsPrincipal user, string downstreamApiName, CancellationToken cancellationToken)
    {
        using var scope = logger.BeginScope(OidcLogScopes.Create(
            traceIdentifier: Activity.Current?.Id ?? Guid.NewGuid().ToString("n"),
            providerName: activeProviderOptions.Value.ProviderName,
            downstreamApiName: downstreamApiName,
            flowStep: "access-token"));

        OidcTokenProviderLog.AccessTokenRequested(logger, downstreamApiName, user.Identity?.IsAuthenticated is true);

        if (user.Identity?.IsAuthenticated is not true)
        {
            throw new OidcReauthenticationRequiredException("A downstream access token can only be requested for an authenticated user.");
        }

        _ = downstreamApiCatalog.GetRequired(downstreamApiName);
        var requestedScopes = scopeResolver.GetRequiredApiScopes(downstreamApiName);
        var entry = await tokenStore.GetApiTokenAsync(user, downstreamApiName, requestedScopes, cancellationToken);

        var refreshSkew = TimeSpan.FromSeconds(tokenCacheOptions.Value.RefreshBeforeExpirationSeconds);
        var refreshRequired = NeedsRefresh(entry, refreshSkew);
        OidcTokenProviderLog.ApiTokenCacheEvaluated(logger, downstreamApiName, entry is not null, refreshRequired);
        if (!refreshRequired)
        {
            return entry!.AccessToken;
        }

        OidcTokenProviderLog.RefreshLockWaiting(logger, downstreamApiName);
        await using var refreshLock = await refreshLockProvider.AcquireAsync(user, downstreamApiName, cancellationToken);
        OidcTokenProviderLog.RefreshLockAcquired(logger, downstreamApiName);

        entry = await tokenStore.GetApiTokenAsync(user, downstreamApiName, requestedScopes, cancellationToken);
        refreshRequired = NeedsRefresh(entry, refreshSkew);
        OidcTokenProviderLog.ApiTokenCacheEvaluated(logger, downstreamApiName, entry is not null, refreshRequired);
        if (!refreshRequired)
        {
            return entry!.AccessToken;
        }

        var sessionTokenSet = await GetRequiredSessionTokenSetAsync(user, downstreamApiName, cancellationToken);
        if (string.IsNullOrWhiteSpace(sessionTokenSet.RefreshToken))
        {
            OidcTokenProviderLog.RefreshTokenMissing(logger, downstreamApiName, hasRefreshToken: false);
            throw new OidcReauthenticationRequiredException("The stored token set does not contain a refresh token, so a new sign-in is required.");
        }

        var openIdOptions = openIdConnectOptionsMonitor.Get(OpenIdConnectDefaults.AuthenticationScheme);
        var tokenEndpoint = await GetTokenEndpointAsync(openIdOptions, cancellationToken, downstreamApiName);
        if (string.IsNullOrWhiteSpace(tokenEndpoint))
        {
            throw new OidcTokenRefreshFailedException("The OIDC token endpoint is not available from the static configuration or the OIDC metadata.");
        }

        var httpsRequirementError = OidcEndpointHttpsValidator.GetProductionRequirementError(tokenEndpoint, hostEnvironment, "the OIDC token endpoint");
        if (httpsRequirementError is not null)
        {
            throw new OidcTokenRefreshFailedException(httpsRequirementError);
        }

        var refreshRequestBody = new Dictionary<string, string>
        {
            [OpenIdConnectParameterNames.GrantType] = OpenIdConnectGrantTypes.RefreshToken,
            [OpenIdConnectParameterNames.RefreshToken] = sessionTokenSet.RefreshToken,
            [OpenIdConnectParameterNames.ClientId] = oidcOptions.Value.ClientId,
            [OpenIdConnectParameterNames.Scope] = string.Join(" ", requestedScopes)
        };
        ApplyClientAuthentication(refreshRequestBody, tokenEndpoint);

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(refreshRequestBody)
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OidcAuthenticationConstants.MediaTypes.Json));

        using var client = httpClientFactory.CreateClient();
        OidcTokenProviderLog.RefreshRequestStarted(logger, activeProviderOptions.Value.ProviderName, downstreamApiName);
        using var response = await SendRefreshRequestAsync(client, request, cancellationToken, downstreamApiName);
        OidcTokenProviderLog.RefreshResponseReceived(logger, activeProviderOptions.Value.ProviderName, downstreamApiName, (int)response.StatusCode);
        if (!response.IsSuccessStatusCode)
        {
            var errorPayload = await response.Content.ReadAsStringAsync(cancellationToken);
            var oauthError = TryGetOAuthError(errorPayload) ?? "unknown";
            OidcTokenProviderLog.RefreshHttpFailed(logger, activeProviderOptions.Value.ProviderName, downstreamApiName, (int)response.StatusCode, oauthError);
            throw CreateRefreshFailureException(response.StatusCode, errorPayload);
        }

        using var document = await ParseRefreshResponseAsync(response, cancellationToken, downstreamApiName);
        OidcTokenProviderLog.RefreshResponseParsed(logger, activeProviderOptions.Value.ProviderName, downstreamApiName);
        var root = document.RootElement;

        var accessToken = root.TryGetProperty(OpenIdConnectParameterNames.AccessToken, out var accessTokenElement)
            ? accessTokenElement.GetString()
            : null;
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new OidcReauthenticationRequiredException("The token endpoint response did not contain an access token.");
        }

        ValidateAdvertisedScopes(downstreamApiName, requestedScopes, accessToken);

        var expiresInSeconds = root.TryGetProperty(OidcAuthenticationConstants.TokenNames.ExpiresIn, out var expiresInElement) && expiresInElement.TryGetInt32(out var parsedExpiresIn)
            ? parsedExpiresIn
            : 300;

        var refreshedTokenSet = new CachedDownstreamApiTokenEntry
        {
            AccessToken = accessToken,
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(expiresInSeconds)
        };

        var refreshedSessionTokenSet = new StoredOidcSessionTokenSet
        {
            RefreshToken = root.TryGetProperty(OpenIdConnectParameterNames.RefreshToken, out var refreshTokenElement)
                ? refreshTokenElement.GetString() ?? sessionTokenSet.RefreshToken
                : sessionTokenSet.RefreshToken,
            IdToken = root.TryGetProperty(OpenIdConnectParameterNames.IdToken, out var idTokenElement)
                ? idTokenElement.GetString() ?? sessionTokenSet.IdToken
                : sessionTokenSet.IdToken,
            ExpiresAtUtc = sessionTokenSet.ExpiresAtUtc
        };

        await tokenStore.StoreSessionTokenSetAsync(user, refreshedSessionTokenSet, cancellationToken);
        await tokenStore.StoreApiTokenAsync(user, downstreamApiName, requestedScopes, refreshedTokenSet, cancellationToken);
        OidcTokenProviderLog.RefreshedTokensStored(logger, activeProviderOptions.Value.ProviderName, downstreamApiName, "success");
        return refreshedTokenSet.AccessToken;
    }

    private async Task<StoredOidcSessionTokenSet> GetRequiredSessionTokenSetAsync(ClaimsPrincipal user, string downstreamApiName, CancellationToken cancellationToken)
    {
        var tokenSet = await tokenStore.GetSessionTokenSetAsync(user, cancellationToken);
        if (tokenSet is not null)
        {
            return tokenSet;
        }

        OidcTokenProviderLog.SessionTokenMissing(logger, downstreamApiName);
        throw new OidcReauthenticationRequiredException("No stored token set was found for the authenticated user.");
    }

    private static bool NeedsRefresh(CachedDownstreamApiTokenEntry? entry, TimeSpan refreshSkew)
    {
        return entry is null || entry.ExpiresAtUtc <= DateTimeOffset.UtcNow.Add(refreshSkew);
    }

    private void ApplyClientAuthentication(IDictionary<string, string> formValues, string tokenEndpoint)
    {
        switch (oidcOptions.Value.ClientAuthenticationMethod)
        {
            case OidcClientAuthenticationMethod.ClientSecretPost:
                formValues[OpenIdConnectParameterNames.ClientSecret] = oidcOptions.Value.ClientSecret
                    ?? throw new InvalidOperationException("ClientSecretPost authentication requires a client secret.");
                break;
            case OidcClientAuthenticationMethod.PrivateKeyJwt:
                var assertionService = clientAssertionService
                    ?? throw new InvalidOperationException("PrivateKeyJwt authentication requires the OIDC client assertion service.");
                formValues[OidcAuthenticationConstants.TokenNames.ClientAssertionType] = OidcAuthenticationConstants.ClientAssertions.JwtBearerType;
                formValues[OpenIdConnectParameterNames.ClientAssertion] = assertionService.CreateClientAssertion(tokenEndpoint);
                break;
            default:
                throw new InvalidOperationException($"Unsupported client authentication method '{oidcOptions.Value.ClientAuthenticationMethod}'.");
        }
    }

    private void ValidateAdvertisedScopes(string downstreamApiName, IReadOnlyCollection<string> requestedScopes, string accessToken)
    {
        var tokenScopes = TryReadAdvertisedScopes(accessToken);
        if (tokenScopes is null)
        {
            return;
        }

        if (tokenScopes.Length == 0)
        {
            OidcTokenProviderLog.ScopeValidationIncomplete(logger, downstreamApiName, string.Join(", ", requestedScopes));
            return;
        }

        var missingScopes = requestedScopes.Except(tokenScopes, StringComparer.Ordinal).ToArray();
        if (missingScopes.Length == 0)
        {
            return;
        }

        OidcTokenProviderLog.ScopeValidationMismatch(
            logger,
            downstreamApiName,
            string.Join(", ", requestedScopes),
            string.Join(", ", tokenScopes),
            string.Join(", ", missingScopes));
    }

    private static string[]? TryReadAdvertisedScopes(string accessToken)
    {
        var handler = new JsonWebTokenHandler();
        if (!handler.CanReadToken(accessToken))
        {
            return null;
        }

        JsonWebToken jwt;
        try
        {
            jwt = handler.ReadJsonWebToken(accessToken);
        }
        catch (ArgumentException)
        {
            return null;
        }

        var rawScopeValue = TryGetClaimValue(jwt, OidcAuthenticationConstants.TokenNames.Scope)
            ?? TryGetClaimValue(jwt, OidcAuthenticationConstants.TokenNames.Scp);

        return rawScopeValue is null
            ? []
            : OidcScopeResolver.NormalizeScopes(rawScopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    private static string? TryGetClaimValue(JsonWebToken jwt, string claimName)
    {
        try
        {
            return jwt.GetClaim(claimName)?.Value;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private async Task<string?> GetTokenEndpointAsync(
        OpenIdConnectOptions openIdOptions,
        CancellationToken cancellationToken,
        string downstreamApiName)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(openIdOptions.Configuration?.TokenEndpoint) &&
                openIdOptions.ConfigurationManager is not null)
            {
                OidcTokenProviderLog.OidcMetadataRequested(logger, activeProviderOptions.Value.ProviderName);
            }

            var resolution = await OidcTokenEndpointResolver.ResolveAsync(openIdOptions, cancellationToken);
            if (resolution.UsedMetadata)
            {
                OidcTokenProviderLog.OidcMetadataLoaded(logger, activeProviderOptions.Value.ProviderName, !string.IsNullOrWhiteSpace(resolution.TokenEndpoint));
            }

            return resolution.TokenEndpoint;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            OidcTokenProviderLog.RefreshTransportFailed(logger, ex, activeProviderOptions.Value.ProviderName, downstreamApiName, ex.GetType().Name);
            throw new OidcTokenRefreshFailedException("Failed to load OIDC metadata for refresh token exchange.", ex);
        }
    }

    private async Task<HttpResponseMessage> SendRefreshRequestAsync(
        HttpClient client,
        HttpRequestMessage request,
        CancellationToken cancellationToken,
        string downstreamApiName)
    {
        try
        {
            return await client.SendAsync(request, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            OidcTokenProviderLog.RefreshTransportFailed(logger, ex, activeProviderOptions.Value.ProviderName, downstreamApiName, ex.GetType().Name);
            throw new OidcTokenRefreshFailedException("Refresh token exchange failed due to a transport error.", ex);
        }
    }

    private async Task<JsonDocument> ParseRefreshResponseAsync(HttpResponseMessage response, CancellationToken cancellationToken, string downstreamApiName)
    {
        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            return await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            OidcTokenProviderLog.RefreshResponseInvalid(logger, ex, activeProviderOptions.Value.ProviderName, downstreamApiName, ex.GetType().Name);
            throw new OidcTokenRefreshFailedException("The token endpoint returned an invalid JSON payload.", ex);
        }
    }

    private static Exception CreateRefreshFailureException(HttpStatusCode statusCode, string errorPayload)
    {
        var oauthError = TryGetOAuthError(errorPayload);
        if (statusCode == HttpStatusCode.BadRequest && string.Equals(oauthError, OidcAuthenticationConstants.OAuthErrors.InvalidGrant, StringComparison.Ordinal))
        {
            return new OidcReauthenticationRequiredException($"Refresh token exchange failed: {(int)statusCode} {oauthError ?? "unknown_error"}");
        }

        return new OidcTokenRefreshFailedException($"Refresh token exchange failed: {(int)statusCode} {oauthError ?? "unknown_error"}");
    }

    private static string? TryGetOAuthError(string errorPayload)
    {
        if (string.IsNullOrWhiteSpace(errorPayload))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(errorPayload);
            return document.RootElement.TryGetProperty(OidcAuthenticationConstants.TokenNames.Error, out var errorElement)
                ? errorElement.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
