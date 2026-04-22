using Microsoft.Extensions.Logging;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;

internal static class OidcLogEvents
{
    public static readonly EventId InfrastructureSummary = new(1000, nameof(InfrastructureSummary));
    public static readonly EventId ForwardedHeadersMode = new(1001, nameof(ForwardedHeadersMode));
    public static readonly EventId StartupValidationFailure = new(1002, nameof(StartupValidationFailure));
    public static readonly EventId RemoteFailureIntercepted = new(1003, nameof(RemoteFailureIntercepted));
    public static readonly EventId RemoteFailureRedirected = new(1004, nameof(RemoteFailureRedirected));
    public static readonly EventId TicketReceived = new(1005, nameof(TicketReceived));
    public static readonly EventId SessionTokenPersisted = new(1006, nameof(SessionTokenPersisted));
    public static readonly EventId TicketTokensCleared = new(1007, nameof(TicketTokensCleared));

    public static readonly EventId LoginRequested = new(2000, nameof(LoginRequested));
    public static readonly EventId LogoutRequested = new(2001, nameof(LogoutRequested));
    public static readonly EventId LogoutCompleted = new(2002, nameof(LogoutCompleted));
    public static readonly EventId AntiforgeryValidationFailed = new(2003, nameof(AntiforgeryValidationFailed));
    public static readonly EventId SessionValidationStarted = new(2004, nameof(SessionValidationStarted));
    public static readonly EventId SessionValidationSucceeded = new(2005, nameof(SessionValidationSucceeded));
    public static readonly EventId SessionValidationFailed = new(2006, nameof(SessionValidationFailed));
    public static readonly EventId SessionValidationUnavailable = new(2007, nameof(SessionValidationUnavailable));

    public static readonly EventId AccessTokenRequested = new(3000, nameof(AccessTokenRequested));
    public static readonly EventId ApiTokenCacheEvaluated = new(3001, nameof(ApiTokenCacheEvaluated));
    public static readonly EventId RefreshLockWaiting = new(3002, nameof(RefreshLockWaiting));
    public static readonly EventId RefreshLockAcquired = new(3003, nameof(RefreshLockAcquired));
    public static readonly EventId SessionTokenMissing = new(3004, nameof(SessionTokenMissing));
    public static readonly EventId RefreshTokenMissing = new(3005, nameof(RefreshTokenMissing));
    public static readonly EventId OidcMetadataRequested = new(3006, nameof(OidcMetadataRequested));
    public static readonly EventId OidcMetadataLoaded = new(3007, nameof(OidcMetadataLoaded));
    public static readonly EventId RefreshRequestStarted = new(3008, nameof(RefreshRequestStarted));
    public static readonly EventId RefreshResponseReceived = new(3009, nameof(RefreshResponseReceived));
    public static readonly EventId RefreshHttpFailed = new(3010, nameof(RefreshHttpFailed));
    public static readonly EventId RefreshResponseParsed = new(3011, nameof(RefreshResponseParsed));
    public static readonly EventId RefreshedTokensStored = new(3012, nameof(RefreshedTokensStored));
    public static readonly EventId RefreshTransportFailed = new(3013, nameof(RefreshTransportFailed));
    public static readonly EventId ScopeValidationIncomplete = new(3014, nameof(ScopeValidationIncomplete));
    public static readonly EventId ScopeValidationMismatch = new(3015, nameof(ScopeValidationMismatch));
    public static readonly EventId RefreshResponseInvalid = new(3016, nameof(RefreshResponseInvalid));

    public static readonly EventId SessionTokenCacheRead = new(4000, nameof(SessionTokenCacheRead));
    public static readonly EventId ApiTokenCacheRead = new(4001, nameof(ApiTokenCacheRead));
    public static readonly EventId SessionTokenCacheWrite = new(4002, nameof(SessionTokenCacheWrite));
    public static readonly EventId ApiTokenCacheWrite = new(4003, nameof(ApiTokenCacheWrite));
    public static readonly EventId TokenStoreRemoveStarted = new(4004, nameof(TokenStoreRemoveStarted));
    public static readonly EventId TokenStoreRemoveCompleted = new(4005, nameof(TokenStoreRemoveCompleted));
    public static readonly EventId TokenStorePayloadInvalid = new(4006, nameof(TokenStorePayloadInvalid));

    public static readonly EventId SessionCleanupStarted = new(5000, nameof(SessionCleanupStarted));
    public static readonly EventId SessionCleanupTokensRemoved = new(5001, nameof(SessionCleanupTokensRemoved));
    public static readonly EventId SessionCleanupCookieCleared = new(5002, nameof(SessionCleanupCookieCleared));
    public static readonly EventId SessionCleanupUnauthorizedWritten = new(5003, nameof(SessionCleanupUnauthorizedWritten));
    public static readonly EventId SessionAbsoluteTimeoutExpired = new(5004, nameof(SessionAbsoluteTimeoutExpired));

    public static readonly EventId AuthorizationRedirectSuppressed = new(6000, nameof(AuthorizationRedirectSuppressed));
    public static readonly EventId AuthorizationStatusCodeWritten = new(6001, nameof(AuthorizationStatusCodeWritten));
}

internal static class OidcLogScopes
{
    public static Dictionary<string, object?> Create(
        string traceIdentifier,
        string? providerName = null,
        string? downstreamApiName = null,
        string? endpoint = null,
        string? flowStep = null)
    {
        var scope = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["TraceIdentifier"] = traceIdentifier
        };

        if (!string.IsNullOrWhiteSpace(providerName))
        {
            scope["ProviderName"] = providerName;
        }

        if (!string.IsNullOrWhiteSpace(downstreamApiName))
        {
            scope["DownstreamApiName"] = downstreamApiName;
        }

        if (!string.IsNullOrWhiteSpace(endpoint))
        {
            scope["Endpoint"] = endpoint;
        }

        if (!string.IsNullOrWhiteSpace(flowStep))
        {
            scope["FlowStep"] = flowStep;
        }

        return scope;
    }
}

internal static partial class OidcInfrastructureLog
{
    [LoggerMessage(EventId = 1000, Level = LogLevel.Debug, Message = "OIDC infrastructure initialized. ProviderName={ProviderName}, DownstreamApis={DownstreamApis}, SessionValidationDownstreamApiName={SessionValidationDownstreamApiName}, ForwardedHeadersEnabled={ForwardedHeadersEnabled}, HasDataProtectionKeysPath={HasDataProtectionKeysPath}")]
    public static partial void InfrastructureInitialized(ILogger logger, string providerName, string downstreamApis, string sessionValidationDownstreamApiName, bool forwardedHeadersEnabled, bool hasDataProtectionKeysPath);

    [LoggerMessage(EventId = 1001, Level = LogLevel.Debug, Message = "Forwarded headers middleware configuration evaluated. Enabled={Enabled}")]
    public static partial void ForwardedHeadersModeEvaluated(ILogger logger, bool enabled);

    [LoggerMessage(EventId = 1002, Level = LogLevel.Error, Message = "OIDC startup validation failed. ValidationStep={ValidationStep}, Reason={Reason}")]
    public static partial void StartupValidationFailed(ILogger logger, string validationStep, string reason);

    [LoggerMessage(EventId = 1003, Level = LogLevel.Warning, Message = "Handled OIDC remote failure detected. ProviderName={ProviderName}, FailureKind={FailureKind}, Error={Error}, RedirectPlanned={RedirectPlanned}, CleanupTransientCookies={CleanupTransientCookies}")]
    public static partial void RemoteFailureIntercepted(ILogger logger, string providerName, string failureKind, string error, bool redirectPlanned, bool cleanupTransientCookies);

    [LoggerMessage(EventId = 1004, Level = LogLevel.Debug, Message = "OIDC remote failure redirected to safe path. ProviderName={ProviderName}, FailureKind={FailureKind}, CleanupTransientCookies={CleanupTransientCookies}")]
    public static partial void RemoteFailureRedirected(ILogger logger, string providerName, string failureKind, bool cleanupTransientCookies);

    [LoggerMessage(EventId = 1005, Level = LogLevel.Debug, Message = "OIDC authentication ticket received from provider {ProviderName}.")]
    public static partial void TicketReceived(ILogger logger, string providerName);

    [LoggerMessage(EventId = 1006, Level = LogLevel.Debug, Message = "OIDC session token set persisted for provider {ProviderName}.")]
    public static partial void SessionTokenPersisted(ILogger logger, string providerName);

    [LoggerMessage(EventId = 1007, Level = LogLevel.Debug, Message = "OIDC ticket tokens cleared from authentication properties for provider {ProviderName}.")]
    public static partial void TicketTokensCleared(ILogger logger, string providerName);
}

internal static partial class OidcEndpointLog
{
    [LoggerMessage(EventId = 2000, Level = LogLevel.Debug, Message = "Authentication login endpoint requested. Endpoint={Endpoint}")]
    public static partial void LoginRequested(ILogger logger, string endpoint);

    [LoggerMessage(EventId = 2001, Level = LogLevel.Debug, Message = "Authentication logout endpoint requested. Endpoint={Endpoint}, IsAuthenticated={IsAuthenticated}")]
    public static partial void LogoutRequested(ILogger logger, string endpoint, bool isAuthenticated);

    [LoggerMessage(EventId = 2002, Level = LogLevel.Debug, Message = "Authentication logout completed. Endpoint={Endpoint}, Result={Result}")]
    public static partial void LogoutCompleted(ILogger logger, string endpoint, string result);

    [LoggerMessage(EventId = 2003, Level = LogLevel.Warning, Message = "Authentication antiforgery validation failed. Endpoint={Endpoint}, ValidationSource={ValidationSource}")]
    public static partial void AntiforgeryValidationFailed(ILogger logger, string endpoint, string validationSource);

    [LoggerMessage(EventId = 2004, Level = LogLevel.Debug, Message = "Authentication session validation started. Endpoint={Endpoint}, IsAuthenticated={IsAuthenticated}, HasSessionValidationApi={HasSessionValidationApi}")]
    public static partial void SessionValidationStarted(ILogger logger, string endpoint, bool isAuthenticated, bool hasSessionValidationApi);

    [LoggerMessage(EventId = 2005, Level = LogLevel.Information, Message = "Authentication session validation succeeded. Endpoint={Endpoint}, Result={Result}")]
    public static partial void SessionValidationSucceeded(ILogger logger, string endpoint, string result);

    [LoggerMessage(EventId = 2006, Level = LogLevel.Warning, Message = "Authentication session validation requires reauthentication. Endpoint={Endpoint}, Result={Result}")]
    public static partial void SessionValidationFailed(ILogger logger, string endpoint, string result);

    [LoggerMessage(EventId = 2007, Level = LogLevel.Error, Message = "Authentication session validation failed due to downstream service unavailability. Endpoint={Endpoint}, Result={Result}")]
    public static partial void SessionValidationUnavailable(ILogger logger, string endpoint, string result);
}

internal static partial class OidcTokenProviderLog
{
    [LoggerMessage(EventId = 3000, Level = LogLevel.Debug, Message = "Downstream access token requested. DownstreamApiName={DownstreamApiName}, IsAuthenticated={IsAuthenticated}")]
    public static partial void AccessTokenRequested(ILogger logger, string downstreamApiName, bool isAuthenticated);

    [LoggerMessage(EventId = 3001, Level = LogLevel.Debug, Message = "Downstream API token cache evaluated. DownstreamApiName={DownstreamApiName}, CacheHit={CacheHit}, RefreshRequired={RefreshRequired}")]
    public static partial void ApiTokenCacheEvaluated(ILogger logger, string downstreamApiName, bool cacheHit, bool refreshRequired);

    [LoggerMessage(EventId = 3002, Level = LogLevel.Debug, Message = "Waiting for downstream token refresh lock. DownstreamApiName={DownstreamApiName}")]
    public static partial void RefreshLockWaiting(ILogger logger, string downstreamApiName);

    [LoggerMessage(EventId = 3003, Level = LogLevel.Debug, Message = "Acquired downstream token refresh lock. DownstreamApiName={DownstreamApiName}")]
    public static partial void RefreshLockAcquired(ILogger logger, string downstreamApiName);

    [LoggerMessage(EventId = 3004, Level = LogLevel.Warning, Message = "Stored OIDC session token set is missing. DownstreamApiName={DownstreamApiName}")]
    public static partial void SessionTokenMissing(ILogger logger, string downstreamApiName);

    [LoggerMessage(EventId = 3005, Level = LogLevel.Warning, Message = "Stored OIDC session token set does not contain a refresh token. DownstreamApiName={DownstreamApiName}, HasRefreshToken={HasRefreshToken}")]
    public static partial void RefreshTokenMissing(ILogger logger, string downstreamApiName, bool hasRefreshToken);

    [LoggerMessage(EventId = 3006, Level = LogLevel.Debug, Message = "Loading OIDC metadata for token refresh. ProviderName={ProviderName}")]
    public static partial void OidcMetadataRequested(ILogger logger, string providerName);

    [LoggerMessage(EventId = 3007, Level = LogLevel.Debug, Message = "Loaded OIDC metadata for token refresh. ProviderName={ProviderName}, HasTokenEndpoint={HasTokenEndpoint}")]
    public static partial void OidcMetadataLoaded(ILogger logger, string providerName, bool hasTokenEndpoint);

    [LoggerMessage(EventId = 3008, Level = LogLevel.Information, Message = "Starting refresh token exchange. ProviderName={ProviderName}, DownstreamApiName={DownstreamApiName}")]
    public static partial void RefreshRequestStarted(ILogger logger, string providerName, string downstreamApiName);

    [LoggerMessage(EventId = 3009, Level = LogLevel.Information, Message = "Refresh token exchange completed. ProviderName={ProviderName}, DownstreamApiName={DownstreamApiName}, StatusCode={StatusCode}")]
    public static partial void RefreshResponseReceived(ILogger logger, string providerName, string downstreamApiName, int statusCode);

    [LoggerMessage(EventId = 3010, Level = LogLevel.Error, Message = "Refresh token exchange failed. ProviderName={ProviderName}, DownstreamApiName={DownstreamApiName}, StatusCode={StatusCode}, ErrorCategory={ErrorCategory}")]
    public static partial void RefreshHttpFailed(ILogger logger, string providerName, string downstreamApiName, int statusCode, string errorCategory);

    [LoggerMessage(EventId = 3011, Level = LogLevel.Debug, Message = "Parsed refresh token response successfully. ProviderName={ProviderName}, DownstreamApiName={DownstreamApiName}")]
    public static partial void RefreshResponseParsed(ILogger logger, string providerName, string downstreamApiName);

    [LoggerMessage(EventId = 3012, Level = LogLevel.Information, Message = "Stored refreshed downstream tokens. ProviderName={ProviderName}, DownstreamApiName={DownstreamApiName}, Result={Result}")]
    public static partial void RefreshedTokensStored(ILogger logger, string providerName, string downstreamApiName, string result);

    [LoggerMessage(EventId = 3013, Level = LogLevel.Error, Message = "Refresh token exchange transport failure. ProviderName={ProviderName}, DownstreamApiName={DownstreamApiName}, ExceptionType={ExceptionType}")]
    public static partial void RefreshTransportFailed(ILogger logger, Exception exception, string providerName, string downstreamApiName, string exceptionType);

    [LoggerMessage(EventId = 3014, Level = LogLevel.Warning, Message = "Downstream access token scope validation could not be fully confirmed. DownstreamApiName={DownstreamApiName}, RequestedScopes={RequestedScopes}")]
    public static partial void ScopeValidationIncomplete(ILogger logger, string downstreamApiName, string requestedScopes);

    [LoggerMessage(EventId = 3015, Level = LogLevel.Warning, Message = "Downstream access token scope validation mismatch. DownstreamApiName={DownstreamApiName}, RequestedScopes={RequestedScopes}, TokenScopes={TokenScopes}, MissingScopes={MissingScopes}")]
    public static partial void ScopeValidationMismatch(ILogger logger, string downstreamApiName, string requestedScopes, string tokenScopes, string missingScopes);

    [LoggerMessage(EventId = 3016, Level = LogLevel.Error, Message = "Refresh token response payload was invalid. ProviderName={ProviderName}, DownstreamApiName={DownstreamApiName}, ExceptionType={ExceptionType}")]
    public static partial void RefreshResponseInvalid(ILogger logger, Exception exception, string providerName, string downstreamApiName, string exceptionType);
}

internal static partial class OidcTokenStoreLog
{
    [LoggerMessage(EventId = 4000, Level = LogLevel.Debug, Message = "OIDC session token cache read completed. CacheHit={CacheHit}")]
    public static partial void SessionTokenCacheRead(ILogger logger, bool cacheHit);

    [LoggerMessage(EventId = 4001, Level = LogLevel.Debug, Message = "Downstream API token cache read completed. DownstreamApiName={DownstreamApiName}, CacheHit={CacheHit}")]
    public static partial void ApiTokenCacheRead(ILogger logger, string downstreamApiName, bool cacheHit);

    [LoggerMessage(EventId = 4002, Level = LogLevel.Debug, Message = "OIDC session token cache write completed. Result={Result}")]
    public static partial void SessionTokenCacheWrite(ILogger logger, string result);

    [LoggerMessage(EventId = 4003, Level = LogLevel.Debug, Message = "Downstream API token cache write completed. DownstreamApiName={DownstreamApiName}, Result={Result}")]
    public static partial void ApiTokenCacheWrite(ILogger logger, string downstreamApiName, string result);

    [LoggerMessage(EventId = 4004, Level = LogLevel.Debug, Message = "OIDC token store removal started.")]
    public static partial void TokenStoreRemoveStarted(ILogger logger);

    [LoggerMessage(EventId = 4005, Level = LogLevel.Debug, Message = "OIDC token store removal completed. RemovedApiTokens={RemovedApiTokens}")]
    public static partial void TokenStoreRemoveCompleted(ILogger logger, int removedApiTokens);

    [LoggerMessage(EventId = 4006, Level = LogLevel.Warning, Message = "OIDC token store payload could not be read. CacheEntryType={CacheEntryType}, FailureCategory={FailureCategory}")]
    public static partial void TokenStorePayloadInvalid(ILogger logger, Exception exception, string cacheEntryType, string failureCategory);
}

internal static partial class OidcSessionCleanupLog
{
    [LoggerMessage(EventId = 5000, Level = LogLevel.Debug, Message = "OIDC session cleanup started. Reason={Reason}, IsAuthenticated={IsAuthenticated}")]
    public static partial void SessionCleanupStarted(ILogger logger, string reason, bool isAuthenticated);

    [LoggerMessage(EventId = 5001, Level = LogLevel.Debug, Message = "OIDC session cleanup removed stored tokens. Reason={Reason}")]
    public static partial void SessionCleanupTokensRemoved(ILogger logger, string reason);

    [LoggerMessage(EventId = 5002, Level = LogLevel.Debug, Message = "OIDC session cleanup cleared cookie authentication state. Reason={Reason}")]
    public static partial void SessionCleanupCookieCleared(ILogger logger, string reason);

    [LoggerMessage(EventId = 5003, Level = LogLevel.Debug, Message = "OIDC session cleanup wrote unauthorized response with reauthentication header. Reason={Reason}, StatusCode={StatusCode}")]
    public static partial void SessionCleanupUnauthorizedWritten(ILogger logger, string reason, int statusCode);

    [LoggerMessage(EventId = 5004, Level = LogLevel.Warning, Message = "OIDC session exceeded the configured absolute timeout. Path={Path}, AbsoluteExpiresAtUtc={AbsoluteExpiresAtUtc}")]
    public static partial void SessionAbsoluteTimeoutExpired(ILogger logger, string path, DateTimeOffset absoluteExpiresAtUtc);
}

internal static partial class OidcAuthorizationLog
{
    [LoggerMessage(EventId = 6000, Level = LogLevel.Debug, Message = "Authentication redirect suppression evaluated. Suppressed={Suppressed}, Reason={Reason}")]
    public static partial void AuthorizationRedirectSuppressed(ILogger logger, bool suppressed, string reason);

    [LoggerMessage(EventId = 6001, Level = LogLevel.Information, Message = "Authentication middleware wrote status code instead of redirect. StatusCode={StatusCode}, Reason={Reason}")]
    public static partial void AuthorizationStatusCodeWritten(ILogger logger, int statusCode, string reason);
}
