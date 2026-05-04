# Release History

This file contains the release history for `Recrovit.AspNetCore.Authentication.OpenIdConnect`.

## [10.1.0] - Unreleased

### Features Added

- Certificate-based client authentication
  - Added certificate loader and certificate option support for OIDC client authentication.
  - Added `private_key_jwt` client assertion support for certificate-backed authentication flows.
- Client assertion extensibility
  - Added a public `IOidcClientAssertionService` abstraction.
  - Added constructor and dependency injection support for custom client assertion handling.

### Bugs Fixed

- Token endpoint resolution improvements
  - Added dynamic token endpoint resolution for authorization code redemption.
  - Refactored downstream token flows to use the resolved token endpoint more consistently.

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
