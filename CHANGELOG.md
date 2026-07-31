# Release History

This file contains the release history for `Recrovit.AspNetCore.Authentication.OpenIdConnect`.

## [Unreleased]

### Features Added

- Extensible Data Protection configuration
  - Added a new `AddOidcAuthenticationInfrastructure(..., Action<IDataProtectionBuilder>? configureDataProtection)` overload so host applications can extend or override the package Data Protection setup.
  - Added `DataProtectionSecurityProfile` with backward-compatible `Standard` behavior and opt-in `Hardened` startup validation.
  - Kept `Recrovit:OpenIdConnect:Infrastructure:DataProtectionKeysPath` supported as a legacy configuration path while allowing host-level or callback-based explicit key repository configuration.

- Provider-specific downstream API overrides
  - Added support for `Recrovit:OpenIdConnect:Providers:<provider>:DownstreamApis` overrides on top of the shared downstream API catalog.
  - Allowed provider-specific downstream API entries to override base URL and relative path values, and to replace the shared scope list when a provider-specific `Scopes` section is present.
  - Added `Disabled` support on downstream API definitions so shared or provider-specific entries can be removed from the effective catalog.

### Bugs Fixed

- Downstream proxy URI hardening
  - Rejected absolute, scheme-relative, and backslash-authority proxy path inputs before any outbound downstream request is created.
  - Enforced exact downstream origin matching for resolved proxy targets so outbound scheme, host, and port remain pinned to the configured downstream API base URL.
  - Constrained resolved proxy targets to the configured downstream root path so requests cannot escape the effective `BaseUrl + RelativePath` prefix while staying on the same origin.
  - Preserved path segments already present on the configured downstream API `BaseUrl` so base-path deployments remain confined to that host-relative root.
  - Rejected dot-segment and multi-pass encoded traversal payloads before any outbound downstream request is created.
  - Returned `400 Bad Request` for invalid downstream proxy paths in both HTTP and transport/WebSocket proxy flows instead of attempting outbound dispatch.
- Downstream proxy transport and response hardening
  - Enforced absolute `https` downstream API base URLs during startup validation in `Production` so proxied WebSocket connections can only resolve to `wss` targets there.
  - Blocked downstream `Set-Cookie` forwarding by default to prevent host-origin cookie injection from proxied responses.
  - Removed hop-by-hop response headers, including headers declared dynamically through `Connection`, before writing proxied downstream responses back to callers.
- Downstream proxy browser-origin protection
  - Expanded the secure-by-default downstream proxy protection policy from `GET`-only to the full generic proxy surface, including WebSocket handshakes.
  - Renamed `Recrovit:OpenIdConnect:Host:DownstreamProxyGetProtection` to `DownstreamProxyRequestProtection` and replaced the old GET-specific options types with request-wide equivalents.
  - Changed the default HTTP policy to accept only `Sec-Fetch-Site: same-origin`, with `same-site` available only through explicit opt-in and `none` rejected in strict mode.
  - Required valid antiforgery tokens for cookie-authenticated unsafe proxy methods after origin policy acceptance, returning `400 Bad Request` on antiforgery failure before any outbound dispatch.
  - Added strict WebSocket `Origin` validation with exact scheme, host, and effective-port matching, explicit allowlists, `null` rejection, and opt-in support for missing `Origin` on non-browser clients.
  - Rejects blocked proxy requests with `403 Forbidden` before any outbound downstream request is created.
- Session token refresh concurrency and cache hardening
  - Added public `ILocalOidcSessionCoordinator` and `ILocalOidcSessionLockLease` contracts with a singleton process-local implementation shared by scoped token stores.
  - Serialized sign-in persistence, API-token writes, refresh rotation, logout, cleanup, and corrupted-cache deletion through one session-scoped local lock.
  - Ordered logout and cleanup so token state is removed before the local cookie is cleared, while preventing refresh persistence from running concurrently for the same session.
  - Prevented compare-and-swap retries from recreating a session aggregate after logout or persisting a refresh result produced from an obsolete rotated refresh token.
  - Reworked stored token persistence around a single versioned session payload so refresh token rotation and downstream API token updates are coordinated through compare-and-swap writes.
  - Changed refresh coordination from per-API in-process locking to session-scoped locking with lease metadata, and wired the provider refresh flow to re-read and retry on concurrent state changes.
  - Added `TokenCacheOptions.DeploymentMode` with `SingleInstance` default behavior and `MultiInstance` fail-fast startup validation when the host keeps the default single-node refresh lock or default non-atomic session-state store.
  - Added public `IOidcSessionRefreshLockProvider` and `IOidcSessionRefreshLockLease` contracts so hosts can replace refresh coordination with cross-node implementations.
  - Tightened the documented `IOidcSessionStateStore` contract so `MultiInstance` deployments require atomic cross-node compare-and-swap semantics for the full session aggregate.
  - Discarded refresh results when the acquired lease has already expired before persistence, and reuses newer stored token state after compare-and-swap contention instead of overwriting it.
  - Deletes corrupted protected session-state payloads from the cache after logging a warning so broken entries deterministically lead to cleanup and reauthentication.
  - Replaced raw subject, issuer, and session-id cache key segments with HMAC-derived session fingerprints so external cache keys no longer expose reversible identity metadata.
  - Removed the separate API-token index model so logout and session cleanup deterministically delete the entire stored token state for the authenticated session.

### Other Changes

- Data Protection diagnostics, tests, and docs
  - Added startup validation and warning coverage for explicit Data Protection repository, application isolation, and key-ring encryption scenarios.
  - Expanded test coverage for callback-based configuration, host-preconfigured Data Protection, and `Standard` versus `Hardened` profile behavior.
  - Updated the README with callback-based configuration, certificate/DPAPI/external KMS examples, and deployment guidance for Data Protection isolation and key rotation.
- Downstream API configuration coverage
  - Added tests covering provider-specific downstream API overrides and disabling behavior.
  - Expanded configuration documentation for provider-level downstream API customization and disabling.
- Proxy regression coverage
  - Added proxy tests for valid relative path handling, origin preservation, empty-path behavior, and rejection of unsafe proxy path forms.
  - Expanded regression coverage for encoded separators, backslash variants, port-switch attempts, transport/WebSocket path validation, and downstream `Set-Cookie` injection filtering.
  - Added regression coverage for strict fetch-metadata evaluation, origin fallback validation, unsafe-method antiforgery enforcement, WebSocket origin allowlists, and explicit missing-origin WebSocket opt-ins.
- Token state architecture and documentation
  - Added `IOidcSessionStateStore`, versioned session-state types, HMAC cache-key derivation, and configuration coverage for the new token-state model.
  - Updated token lifecycle and production configuration documentation to describe the session-aggregate store, shared HMAC secret requirement, deployment-mode semantics, and multi-instance refresh coordination expectations.

### Breaking Changes

- Downstream proxy request protection configuration
  - Renamed `Recrovit:OpenIdConnect:Host:DownstreamProxyGetProtection` to `DownstreamProxyRequestProtection`.
  - Replaced the GET-specific options and enum types with request-wide equivalents: `DownstreamProxyRequestProtectionOptions` and `ProxyRequestProtectionMode`.
  - Tightened the default generic proxy policy so hosts that relied on the previous GET-only protection behavior must update frontend request handling and configuration for unsafe HTTP methods and WebSocket handshakes.


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
