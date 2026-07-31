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
    private readonly IOidcSessionStateStore sessionStateStore;
    private readonly IOidcSessionRefreshLockProvider refreshLockProvider;
    private readonly ILocalOidcSessionCoordinator localSessionCoordinator;
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
    private readonly TimeProvider timeProvider;

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
            GetRequiredSessionStateStore(tokenStore),
            new UserRefreshLockProvider(activeProviderOptions),
            LocalOidcSessionCoordinatorRegistry.GetOrCreate(activeProviderOptions),
            downstreamApiCatalog,
            new OidcScopeResolver(oidcOptions.Value.Scopes, downstreamApiCatalog),
            oidcOptions,
            activeProviderOptions,
            tokenCacheOptions,
            logger,
            httpClientFactory,
            hostEnvironment,
            openIdConnectOptionsMonitor,
            clientAssertionService: null,
            TimeProvider.System)
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
            GetRequiredSessionStateStore(tokenStore),
            new UserRefreshLockProvider(activeProviderOptions),
            LocalOidcSessionCoordinatorRegistry.GetOrCreate(activeProviderOptions),
            downstreamApiCatalog,
            new OidcScopeResolver(oidcOptions.Value.Scopes, downstreamApiCatalog),
            oidcOptions,
            activeProviderOptions,
            tokenCacheOptions,
            logger,
            httpClientFactory,
            hostEnvironment,
            openIdConnectOptionsMonitor,
            clientAssertionService,
            TimeProvider.System)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="OidcDownstreamUserTokenProvider"/> class with explicit local session coordination.
    /// </summary>
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
        IOidcClientAssertionService? clientAssertionService,
        ILocalOidcSessionCoordinator localSessionCoordinator)
        : this(
            tokenStore,
            GetRequiredSessionStateStore(tokenStore),
            new UserRefreshLockProvider(activeProviderOptions),
            localSessionCoordinator,
            downstreamApiCatalog,
            new OidcScopeResolver(oidcOptions.Value.Scopes, downstreamApiCatalog),
            oidcOptions,
            activeProviderOptions,
            tokenCacheOptions,
            logger,
            httpClientFactory,
            hostEnvironment,
            openIdConnectOptionsMonitor,
            clientAssertionService,
            TimeProvider.System)
    {
    }

    internal OidcDownstreamUserTokenProvider(
        IDownstreamUserTokenStore tokenStore,
        IOidcSessionStateStore sessionStateStore,
        IOidcSessionRefreshLockProvider refreshLockProvider,
        ILocalOidcSessionCoordinator localSessionCoordinator,
        DownstreamApiCatalog downstreamApiCatalog,
        OidcScopeResolver scopeResolver,
        IOptions<OidcProviderOptions> oidcOptions,
        IOptions<ActiveOidcProviderOptions> activeProviderOptions,
        IOptions<TokenCacheOptions> tokenCacheOptions,
        ILogger<OidcDownstreamUserTokenProvider> logger,
        IHttpClientFactory httpClientFactory,
        IHostEnvironment hostEnvironment,
        IOptionsMonitor<OpenIdConnectOptions> openIdConnectOptionsMonitor,
        IOidcClientAssertionService? clientAssertionService,
        TimeProvider timeProvider)
    {
        _ = tokenStore;
        this.sessionStateStore = sessionStateStore;
        this.refreshLockProvider = refreshLockProvider;
        this.localSessionCoordinator = localSessionCoordinator;
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
        this.timeProvider = timeProvider;
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
        var entry = await GetApiTokenEntryAsync(user, downstreamApiName, requestedScopes, cancellationToken);

        var refreshSkew = TimeSpan.FromSeconds(tokenCacheOptions.Value.RefreshBeforeExpirationSeconds);
        var refreshRequired = NeedsRefresh(entry, refreshSkew);
        OidcTokenProviderLog.ApiTokenCacheEvaluated(logger, downstreamApiName, entry is not null, refreshRequired);
        if (!refreshRequired)
        {
            return entry!.AccessToken;
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

        var apiTokenKey = OidcSessionStateApiKey.Create(downstreamApiName, requestedScopes);
        using var client = httpClientFactory.CreateClient(OidcHttpClientNames.TokenEndpoint);
        OidcTokenProviderLog.RefreshLockWaiting(logger, downstreamApiName);
        await using var refreshLock = await refreshLockProvider.AcquireAsync(user, cancellationToken);
        using var leaseScope = logger.BeginScope(OidcLogScopes.Create(
            traceIdentifier: Activity.Current?.Id ?? Guid.NewGuid().ToString("n"),
            providerName: activeProviderOptions.Value.ProviderName,
            downstreamApiName: downstreamApiName,
            flowStep: "refresh-lease",
            leaseOwnerToken: refreshLock.OwnerToken,
            leaseExpiresAtUtc: refreshLock.ExpiresAtUtc));
        OidcTokenProviderLog.RefreshLockAcquired(logger, downstreamApiName);

        await using var localSessionLock = await localSessionCoordinator.AcquireAsync(user, cancellationToken);

        var sessionState = await sessionStateStore.GetSessionStateAsync(user, localSessionLock, cancellationToken);
        entry = TryGetApiTokenEntry(sessionState, apiTokenKey);
        refreshRequired = NeedsRefresh(entry, refreshSkew);
        OidcTokenProviderLog.ApiTokenCacheEvaluated(logger, downstreamApiName, entry is not null, refreshRequired);
        if (!refreshRequired)
        {
            return entry!.AccessToken;
        }

        var sessionTokenSet = GetRequiredSessionTokenSet(sessionState, downstreamApiName);
        if (string.IsNullOrWhiteSpace(sessionTokenSet.RefreshToken))
        {
            OidcTokenProviderLog.RefreshTokenMissing(logger, downstreamApiName, hasRefreshToken: false);
            throw new OidcReauthenticationRequiredException("The stored token set does not contain a refresh token, so a new sign-in is required.");
        }

        RefreshResult refreshResult;
        var sourceVersion = sessionState?.Version;
        var sourceRefreshToken = sessionTokenSet.RefreshToken;
        try
        {
            refreshResult = await RefreshTokenSetAsync(
                client,
                tokenEndpoint,
                sessionTokenSet,
                requestedScopes,
                downstreamApiName,
                cancellationToken);
        }
        catch (Exception ex) when (
            ex is not OperationCanceledException &&
            ex is not InvalidOperationException or OidcReauthenticationRequiredException or OidcTokenRefreshFailedException)
        {
            return await HandleRefreshFailureAsync(
                ex,
                user,
                downstreamApiName,
                apiTokenKey,
                refreshSkew,
                sourceVersion,
                sourceRefreshToken,
                localSessionLock,
                cancellationToken);
        }

        var refreshCompletedUtc = timeProvider.GetUtcNow();
        VersionedOidcSessionState? latestState = sessionState;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            if (attempt > 0)
            {
                latestState = await sessionStateStore.GetSessionStateAsync(user, localSessionLock, cancellationToken);
            }

            var latestEntry = TryGetApiTokenEntry(latestState, apiTokenKey);
            if (!NeedsRefresh(latestEntry, refreshSkew))
            {
                OidcTokenProviderLog.RefreshedTokensReusedAfterConcurrentUpdate(logger, activeProviderOptions.Value.ProviderName, downstreamApiName);
                return latestEntry!.AccessToken;
            }

            if (latestState?.State.SessionTokens is null)
            {
                throw new OidcReauthenticationRequiredException(
                    "The authenticated session was removed while the downstream token was being refreshed.");
            }

            if (!string.Equals(
                latestState.State.SessionTokens.RefreshToken,
                sourceRefreshToken,
                StringComparison.Ordinal))
            {
                throw new OidcReauthenticationRequiredException(
                    "The stored refresh token changed while the downstream token was being refreshed.");
            }

            if (RefreshLeaseExpired(refreshLock, downstreamApiName))
            {
                throw new OidcTokenRefreshFailedException("The refreshed token state could not be persisted because the refresh lease expired before the compare-and-swap update completed.");
            }

            var nextState = CreateMergedRefreshedState(
                latestState?.State,
                apiTokenKey,
                refreshResult,
                sourceRefreshToken,
                refreshCompletedUtc);

            if (await sessionStateStore.TryCompareAndSwapSessionStateAsync(
                user,
                latestState?.Version,
                nextState,
                localSessionLock,
                cancellationToken))
            {
                OidcTokenProviderLog.RefreshedTokensStored(logger, activeProviderOptions.Value.ProviderName, downstreamApiName, "success");
                return refreshResult.ApiToken.AccessToken;
            }
        }

        throw new OidcTokenRefreshFailedException("The refreshed token state could not be persisted because a newer session token version was written concurrently.");
    }

    private async Task<CachedDownstreamApiTokenEntry?> GetApiTokenEntryAsync(
        ClaimsPrincipal user,
        string downstreamApiName,
        IReadOnlyCollection<string> requestedScopes,
        CancellationToken cancellationToken)
    {
        var state = await sessionStateStore.GetSessionStateAsync(user, cancellationToken);
        return TryGetApiTokenEntry(state, OidcSessionStateApiKey.Create(downstreamApiName, requestedScopes));
    }

    private static CachedDownstreamApiTokenEntry? TryGetApiTokenEntry(VersionedOidcSessionState? sessionState, string apiTokenKey)
    {
        return sessionState is not null && sessionState.State.ApiTokens.TryGetValue(apiTokenKey, out var entry)
            ? entry.Clone()
            : null;
    }

    private StoredOidcSessionTokenSet GetRequiredSessionTokenSet(VersionedOidcSessionState? sessionState, string downstreamApiName)
    {
        var tokenSet = sessionState?.State.SessionTokens?.Clone();
        if (tokenSet is not null)
        {
            return tokenSet;
        }

        OidcTokenProviderLog.SessionTokenMissing(logger, downstreamApiName);
        throw new OidcReauthenticationRequiredException("No stored token set was found for the authenticated user.");
    }

    private async Task<RefreshResult> RefreshTokenSetAsync(
        HttpClient client,
        string tokenEndpoint,
        StoredOidcSessionTokenSet sessionTokenSet,
        IReadOnlyCollection<string> requestedScopes,
        string downstreamApiName,
        CancellationToken cancellationToken)
    {
        var refreshRequestBody = new Dictionary<string, string>
        {
            [OpenIdConnectParameterNames.GrantType] = OpenIdConnectGrantTypes.RefreshToken,
            [OpenIdConnectParameterNames.RefreshToken] = sessionTokenSet.RefreshToken!,
            [OpenIdConnectParameterNames.ClientId] = oidcOptions.Value.ClientId,
            [OpenIdConnectParameterNames.Scope] = string.Join(" ", requestedScopes)
        };
        ApplyClientAuthentication(refreshRequestBody, tokenEndpoint);

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(refreshRequestBody)
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OidcAuthenticationConstants.MediaTypes.Json));

        OidcTokenProviderLog.RefreshRequestStarted(logger, activeProviderOptions.Value.ProviderName, downstreamApiName);
        using var response = await SendRefreshRequestAsync(client, request, cancellationToken, downstreamApiName);
        OidcTokenProviderLog.RefreshResponseReceived(logger, activeProviderOptions.Value.ProviderName, downstreamApiName, (int)response.StatusCode);
        if (IsRedirectStatusCode(response.StatusCode))
        {
            OidcTokenProviderLog.RefreshHttpFailed(logger, activeProviderOptions.Value.ProviderName, downstreamApiName, (int)response.StatusCode, "redirect_blocked");
            throw new OidcTokenRefreshFailedException(
                $"Refresh token exchange failed: {(int)response.StatusCode} redirect responses are not allowed from the token endpoint.");
        }

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

        return new RefreshResult(
            new CachedDownstreamApiTokenEntry
            {
                AccessToken = accessToken,
                ExpiresAtUtc = timeProvider.GetUtcNow().AddSeconds(expiresInSeconds)
            },
            new StoredOidcSessionTokenSet
            {
                RefreshToken = root.TryGetProperty(OpenIdConnectParameterNames.RefreshToken, out var refreshTokenElement)
                    ? refreshTokenElement.GetString() ?? sessionTokenSet.RefreshToken
                    : sessionTokenSet.RefreshToken,
                IdToken = root.TryGetProperty(OpenIdConnectParameterNames.IdToken, out var idTokenElement)
                    ? idTokenElement.GetString() ?? sessionTokenSet.IdToken
                    : sessionTokenSet.IdToken,
                ExpiresAtUtc = sessionTokenSet.ExpiresAtUtc
            });
    }

    private bool NeedsRefresh(CachedDownstreamApiTokenEntry? entry, TimeSpan refreshSkew)
    {
        return entry is null || entry.ExpiresAtUtc <= timeProvider.GetUtcNow().Add(refreshSkew);
    }

    private async Task<string> HandleRefreshFailureAsync(
        Exception refreshException,
        ClaimsPrincipal user,
        string downstreamApiName,
        string apiTokenKey,
        TimeSpan refreshSkew,
        string? sourceVersion,
        string? sourceRefreshToken,
        ILocalOidcSessionLockLease localSessionLock,
        CancellationToken cancellationToken)
    {
        var latestState = await sessionStateStore.GetSessionStateAsync(user, localSessionLock, cancellationToken);
        var latestEntry = TryGetApiTokenEntry(latestState, apiTokenKey);
        if (!NeedsRefresh(latestEntry, refreshSkew))
        {
            OidcTokenProviderLog.RefreshedTokensReusedAfterConcurrentUpdate(logger, activeProviderOptions.Value.ProviderName, downstreamApiName);
            return latestEntry!.AccessToken;
        }

        if (refreshException is OidcReauthenticationRequiredException && SessionRefreshSourceMatches(latestState, sourceVersion, sourceRefreshToken))
        {
            throw refreshException;
        }

        throw refreshException as OidcTokenRefreshFailedException
            ?? new OidcTokenRefreshFailedException("Refresh token exchange failed and no newer usable token state was found.", refreshException);
    }

    private OidcSessionState CreateMergedRefreshedState(
        OidcSessionState? latestState,
        string apiTokenKey,
        RefreshResult refreshResult,
        string sourceRefreshToken,
        DateTimeOffset refreshCompletedUtc)
    {
        var nextState = (latestState ?? new OidcSessionState()).Clone();
        nextState.ApiTokens[apiTokenKey] = refreshResult.ApiToken.Clone();

        if (string.Equals(nextState.SessionTokens?.RefreshToken, sourceRefreshToken, StringComparison.Ordinal))
        {
            nextState.SessionTokens = refreshResult.SessionTokenSet.Clone();
        }

        nextState.LastRefreshUtc = nextState.LastRefreshUtc is { } lastRefreshUtc && lastRefreshUtc > refreshCompletedUtc
            ? lastRefreshUtc
            : refreshCompletedUtc;
        return nextState;
    }

    private bool RefreshLeaseExpired(IOidcSessionRefreshLockLease refreshLock, string downstreamApiName)
    {
        if (refreshLock.ExpiresAtUtc == DateTimeOffset.MaxValue)
        {
            return false;
        }

        if (timeProvider.GetUtcNow() <= refreshLock.ExpiresAtUtc)
        {
            return false;
        }

        OidcTokenProviderLog.RefreshLockLeaseExpired(logger, activeProviderOptions.Value.ProviderName, downstreamApiName);
        return true;
    }

    private static bool SessionRefreshSourceMatches(
        VersionedOidcSessionState? latestState,
        string? sourceVersion,
        string? sourceRefreshToken)
    {
        return string.Equals(latestState?.Version, sourceVersion, StringComparison.Ordinal) &&
            string.Equals(latestState?.State.SessionTokens?.RefreshToken, sourceRefreshToken, StringComparison.Ordinal);
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
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            OidcTokenProviderLog.RefreshTransportFailed(logger, ex, activeProviderOptions.Value.ProviderName, downstreamApiName, ex.GetType().Name);
            throw new OidcTokenRefreshFailedException("Refresh token exchange failed because the token endpoint request timed out.", ex);
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

    private static IOidcSessionStateStore GetRequiredSessionStateStore(IDownstreamUserTokenStore tokenStore)
    {
        return tokenStore as IOidcSessionStateStore
            ?? throw new InvalidOperationException(
                $"The configured {nameof(IDownstreamUserTokenStore)} must also implement {nameof(IOidcSessionStateStore)}.");
    }

    private static bool IsRedirectStatusCode(HttpStatusCode statusCode)
        => statusCode is HttpStatusCode.MovedPermanently
            or HttpStatusCode.Found
            or HttpStatusCode.SeeOther
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;

    private sealed record RefreshResult(
        CachedDownstreamApiTokenEntry ApiToken,
        StoredOidcSessionTokenSet SessionTokenSet);
}
