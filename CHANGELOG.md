# Release History

This file contains the release history for `Recrovit.AspNetCore.Authentication.OpenIdConnect`.

## [10.2.0] - Unreleased

### Features Added

- Data Protection configuration
  - Added `AddOidcAuthenticationInfrastructure(..., Action<IDataProtectionBuilder>? configureDataProtection)` so hosts can extend the package Data Protection setup.
  - Added `DataProtectionSecurityProfile` with backward-compatible `Standard` behavior and opt-in `Hardened` startup validation.
  - Kept `Recrovit:OpenIdConnect:Infrastructure:DataProtectionKeysPath` supported while allowing callback-based or host-level key repository configuration.

- Downstream API and proxy configuration
  - Added provider-specific `DownstreamApis` overrides, including base URL, relative path, scope replacement, header-list replacement, and `Disabled` support.
  - Added request and response header allowlists to downstream API definitions, plus `IncludeDefaultForwardedRequestHeaders`.
  - Added `MapDownstreamApiProxyEndpoints(Action<DownstreamProxyEndpointOptions> configure, string routePrefix = DefaultRoutePrefix)` with immutable per-API claim-header mappings through `ForwardFirstClaimHeader(...)` and `ForwardClaimValuesHeader(...)`.

- Token session-state and refresh coordination
  - Reworked token persistence around one encrypted, versioned session aggregate instead of separate session/API-token cache entries.
  - Added `IOidcSessionStateStore`, `IOidcSessionRefreshLockProvider`, HMAC-derived cache keys, and `TokenCacheOptions.DeploymentMode`.
  - Added multi-instance fail-fast validation when default single-node refresh locking or default non-atomic session state storage is still registered.

### Bugs Fixed

- Hardened downstream proxy resolution and forwarding
  - Rejected absolute, scheme-relative, backslash-authority, dot-segment, and multi-pass encoded traversal paths before outbound dispatch.
  - Pinned resolved proxy targets to the configured downstream origin and effective `BaseUrl + RelativePath` root.
  - Disabled downstream redirect following and cookie storage for the proxy `HttpClient`.
  - Replaced implicit request-header forwarding with safe defaults and per-API allowlists.
  - Suppressed downstream cookies, CORS headers, host-owned security headers, hop-by-hop headers, and unsafe redirect targets in proxied responses.
  - Protected server-generated claim headers against client spoofing.

- Hardened downstream proxy request protection
  - Expanded proxy browser-origin protection from `GET`-only to the full generic proxy surface, including unsafe HTTP methods and WebSocket handshakes.
  - Renamed `DownstreamProxyGetProtection` to `DownstreamProxyRequestProtection` and replaced GET-specific option types with request-wide equivalents.
  - Required valid antiforgery tokens for cookie-authenticated unsafe proxy methods after origin policy acceptance.
  - Added strict WebSocket `Origin` validation with explicit allowlists, `null` rejection, and opt-in support for missing `Origin` on non-browser clients.

- Hardened token refresh and cleanup
  - Serialized sign-in persistence, API-token writes, refresh rotation, logout, cleanup, and corrupted-cache deletion through a package-internal session-scoped local lock.
  - Prevented refresh compare-and-swap retries from restoring deleted sessions or persisting results produced from obsolete rotated refresh tokens.
  - Reused newer stored token state after compare-and-swap contention instead of overwriting it.
  - Deleted corrupted protected session-state payloads after logging.
  - Replaced raw issuer, subject, and session-id cache key segments with HMAC-derived session fingerprints.
  - Fixed the default refresh lock provider so canceled waits do not leak lease references and lease disposal is idempotent.

### Other Changes

- Documentation and tests
  - Clarified README guidance for provider-specific downstream APIs, proxy request protection, token-cache HMAC secrets, Data Protection configuration, and multi-instance requirements.
  - Added and updated regression coverage for Data Protection validation, downstream API overrides, proxy path/header/origin hardening, token-state persistence, refresh coordination, and cleanup behavior.
  - Kept process-local session coordination as an internal package implementation detail.

### Breaking Changes

- Downstream proxy request protection configuration
  - Renamed `Recrovit:OpenIdConnect:Host:DownstreamProxyGetProtection` to `DownstreamProxyRequestProtection`.
  - Replaced the GET-specific options and enum types with request-wide equivalents: `DownstreamProxyRequestProtectionOptions` and `ProxyRequestProtectionMode`.
  - Tightened the default generic proxy policy so hosts that relied on the previous GET-only protection behavior must update frontend request handling and configuration for unsafe HTTP methods and WebSocket handshakes.
- Downstream proxy header forwarding defaults
  - Removed the previous implicit forwarding behavior, including the client-controlled `rgf-*` wildcard.
  - Changed the default downstream proxy request forwarding policy to a built-in cache/content-negotiation header set with per-API extension and explicit opt-out support through `IncludeDefaultForwardedRequestHeaders`.
  - Clarified that CORS and host-security response policy remains host-owned; downstream response headers in those categories are always suppressed.
- Token-state extensibility
  - Custom token-state stores used for multi-instance deployments must implement `IOidcSessionStateStore` with atomic cross-node compare-and-swap semantics.
  - Process-local session lock interfaces are internal implementation details and are not part of the public package API.


## [10.1.0] - 2026-07-10

### Features Added

- Certificate-based client authentication
  - Added certificate loader and certificate option support for OIDC client authentication.
  - Added `private_key_jwt` client assertion support for certificate-backed authentication flows.
- Client assertion extensibility
  - Added a public `IOidcClientAssertionService` abstraction.
  - Added constructor and dependency injection support for custom client assertion handling.

### Bugs Fixed

- Token endpoint resolution improvements
  - Added dynamic token endpoint resolution for authorization code redemption when the redemption request does not provide the issuer address directly.
  - Updated downstream refresh token exchange to honor a preconfigured `OpenIdConnectOptions.Configuration` before falling back to metadata, and to fail with a controlled error when no token endpoint can be resolved.

### Other Changes

- Test coverage and protocol clarifications
  - Added tests for certificate-based authentication and client assertion behavior.
  - Added ECDSA assertion tests and clarified JWT header handling.
- Documentation updates
  - Expanded configuration guidance for certificate-based client authentication.
  - Clarified `private_key_jwt` certificate requirements and related behavior.

### Breaking Changes

- None.

## [10.0.0] - 2026-04-24

- Initial release
  - Published the first stable package version on the `main` branch.

### Features

- Authentication infrastructure
  - Provides configuration-driven cookie authentication and OpenID Connect registration.
  - Uses an active provider selected from the configured provider catalog.
- Built-in authentication endpoints
  - Includes reusable endpoints for login, logout, session validation, and current principal inspection.
  - Handles selected OpenID Connect callback failures with safe redirects.
- Downstream token management
  - Stores user tokens outside the authentication cookie after sign-in.
  - Exposes `IDownstreamUserTokenProvider` for downstream access token retrieval.
  - Refreshes access tokens automatically when a refresh token is available.
- Proxy and transport support
  - Includes reusable downstream HTTP proxy infrastructure for configured APIs.
  - Supports transport and WebSocket proxy scenarios for OIDC-enabled hosts.
- API-friendly authorization behavior
  - Returns `401` and `403` for API-style and proxy requests instead of interactive login redirects.
  - Applies proxy-aware authorization handling for backend-oriented endpoints.
- Session cleanup and reauthentication signaling
  - Cleans up unusable local session state.
  - Signals when reauthentication is required because stored token state can no longer be used.
- Production and host safeguards
  - Supports forwarded headers for reverse-proxy deployments.
  - Supports shared Data Protection for multi-instance hosts.
  - Validates provider selection, downstream scope consistency, and host security requirements at startup.
