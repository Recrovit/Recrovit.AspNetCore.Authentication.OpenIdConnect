# Recrovit.AspNetCore.Authentication.OpenIdConnect
[![NuGet Version](https://img.shields.io/nuget/v/Recrovit.AspNetCore.Authentication.OpenIdConnect?label=Latest%20release)](https://www.nuget.org/packages/Recrovit.AspNetCore.Authentication.OpenIdConnect/)

`Recrovit.AspNetCore.Authentication.OpenIdConnect` is a reusable ASP.NET Core host infrastructure package for applications that authenticate users with OpenID Connect and then need to keep a usable authenticated session for downstream API access.

It does more than wire up `AddOpenIdConnect`. The package combines cookie-based sign-in, OpenID Connect challenge handling, reusable authentication endpoints, downstream token storage and refresh, API-friendly authorization behavior, and host-level production safeguards into one consistent integration model.

## What Problem It Solves

ASP.NET Core hosts that rely on OpenID Connect often need the same set of behaviors at the same time:

- sign users in with an external identity provider
- keep a local authenticated session in a secure cookie
- retain access to user tokens for later downstream API calls
- refresh expired downstream access tokens without forcing a full sign-in every time
- avoid redirect-based login behavior for API and proxy requests
- keep production deployments safe when multiple instances share authentication state

This package exists to provide that combined host infrastructure as a reusable building block instead of having every application implement it independently.

## Core Capabilities

- Registers cookie authentication and OpenID Connect authentication with a configuration-driven active provider.
- Exposes reusable authentication endpoints for login, logout, session validation, and current principal inspection.
- Stores user token sets outside the authentication cookie after sign-in.
- Provides downstream access tokens for authenticated users through `IDownstreamUserTokenProvider`.
- Redirects handled OIDC callback failures such as canceled or access-denied sign-in flows to a safe application path instead of surfacing the raw callback error.
- Provides reusable downstream HTTP proxy and transport/WebSocket proxy infrastructure for OIDC-enabled hosts.
- Refreshes expired access tokens through the provider's token endpoint when a refresh token is available.
- Returns `401` and `403` for API-style and proxy requests instead of redirecting to an interactive login flow.
- Clears local session state and signals reauthentication when a stored token set is no longer usable.
- Supports forwarded headers and shared Data Protection configuration for reverse-proxy and multi-instance hosts.
- Validates important configuration at startup, including provider selection and downstream scope consistency.

## Benefits

- Reduces repeated host setup code for OpenID Connect-based applications.
- Keeps authentication cookies smaller and cleaner by removing saved tokens from cookie state.
- Centralizes user token lifecycle handling instead of scattering refresh logic across services.
- Makes backend and proxy endpoints behave like APIs instead of browser-only pages.
- Gives hosts a built-in model for signaling that the user must authenticate again.
- Helps prevent production misconfiguration by checking for shared cache and shared Data Protection key requirements.

## Typical Use Cases

- Server-rendered ASP.NET Core hosts that authenticate with an external OIDC identity provider.
- Blazor or hybrid hosts that need reusable login/logout/session endpoints.
- Applications that call one or more downstream APIs on behalf of the signed-in user.
- Reverse-proxy or server-proxy architectures where redirect-based unauthorized behavior is undesirable for API calls.
- BFF-style or server-proxy hosts that proxy downstream APIs and realtime transport endpoints through the authenticated host.
- Multi-instance deployments where authentication state must remain valid across nodes.


# Using Recrovit.AspNetCore.Authentication.OpenIdConnect

`Recrovit.AspNetCore.Authentication.OpenIdConnect` is intended for ASP.NET Core hosts that need interactive OpenID Connect sign-in together with reusable session management and downstream API token handling.

Use it when your host application must:

- authenticate users with an external OIDC provider
- keep a local cookie-based session
- call downstream APIs on behalf of the signed-in user
- proxy downstream HTTP or transport-style endpoints through the authenticated host
- refresh expired access tokens by using a stored refresh token
- return `401` and `403` for API or proxy requests instead of redirecting to a login page

## Minimal Host Integration

Register the infrastructure during application startup:

```csharp
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

var builder = WebApplication.CreateBuilder(args);

builder.AddRecrovitOpenIdConnectInfrastructure();

var app = builder.Build();

app.UseRecrovitOpenIdConnectForwardedHeaders();
app.UseRecrovitOpenIdConnectStatusCodePagesWithReExecute("/not-found", null, true);
app.UseRecrovitOpenIdConnectAuthentication();
app.UseRecrovitOpenIdConnectProxyTransports();

app.MapRecrovitOpenIdConnectEndpoints();

app.Run();
```

The package-level integration surface is built around these extension methods:

- `AddRecrovitOpenIdConnectInfrastructure`
- `UseRecrovitOpenIdConnectForwardedHeaders`
- `UseRecrovitOpenIdConnectStatusCodePagesWithReExecute`
- `UseRecrovitOpenIdConnectAuthentication`
- `UseRecrovitOpenIdConnectProxyTransports`
- `MapRecrovitOpenIdConnectEndpoints`

`UseRecrovitOpenIdConnectAuthentication` also enables ASP.NET Core antiforgery middleware for the package endpoints. If you compose the middleware pipeline manually instead of using this helper, add `app.UseAntiforgery()` before mapping the built-in authentication endpoints.

For production deployments, also replace the default in-memory distributed cache with a shared `IDistributedCache` implementation. A SQL Server example is included later in this document.

## Configuration Structure

The package reads its settings from the `Recrovit:OpenIdConnect` root section.

### `Recrovit:OpenIdConnect:Host`

Bound to `OidcAuthenticationOptions`.

Key responsibilities:

- defines the authentication cookie name
- defines the base path for the built-in authentication endpoints
- defines the safe redirect path used when a handled OIDC remote callback failure returns to the host
- optionally names a downstream API that should be used to validate whether the current session is still usable

### `Recrovit:OpenIdConnect:Provider`

Selects the active provider name. The package requires this value and uses it to resolve the concrete provider configuration from `Providers:<name>`.

### `Recrovit:OpenIdConnect:Providers:<name>`

Bound to `OidcProviderOptions`.

Key responsibilities:

- identity provider authority
- OIDC client credentials and certificate-based client authentication
- callback and sign-out paths
- extra login and identity scopes
- UserInfo loading behavior
- HTTPS metadata enforcement

### `Recrovit:OpenIdConnect:DownstreamApis`

Loaded into `DownstreamApiCatalog` as named `DownstreamApiDefinition` entries.

Each downstream API definition describes:

- `BaseUrl`
- `Scopes`
- `RelativePath`

The catalog is used both for validation and for runtime token access.

At sign-in, the package automatically unions every configured downstream API scope with `Provider:Scopes` so the initial consent surface already covers all configured APIs.

Provider-specific overrides can also be configured under `Recrovit:OpenIdConnect:Providers:<provider>:DownstreamApis`.

Precedence rules:

- the shared `DownstreamApis` section provides the base definition
- provider-specific entries override only the fields they define
- provider-specific `Scopes` replaces the shared scope list when the section is present
- `Disabled: true` removes the downstream API from the effective catalog entirely

Each downstream API definition also supports:

- `Disabled`

## Downstream API Proxy Endpoints

When a host needs to expose configured downstream APIs through the authenticated application, the package can map generic proxy endpoints for every entry in `Recrovit:OpenIdConnect:DownstreamApis`.

Register the endpoints with:

```csharp
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

app.MapDownstreamApiProxyEndpoints();
```

This maps a generic route pattern:

- `/downstream/{apiName}`
- `/downstream/{apiName}/{**path}`

Behavior:

- `apiName` is resolved from `DownstreamApiCatalog`
- the downstream base URL, scopes, and configured `RelativePath` come from the matching `DownstreamApiDefinition`
- the effective downstream proxy root is the configured `BaseUrl + RelativePath`
- if `BaseUrl` already contains a path segment, that path remains part of the downstream root and is not replaced by the proxy route path
- the route path after `/downstream/{apiName}` is appended only within that configured downstream root; attempts to escape it are rejected with `400 Bad Request`
- the host acquires or refreshes the signed-in user's downstream access token through `IDownstreamUserTokenProvider`
- the request is forwarded through the built-in downstream HTTP proxy infrastructure
- cookie-authenticated downstream proxy `GET` requests are protected against cross-site browser initiation by default
- API-style authorization behavior is preserved, so unauthorized proxy requests return `401` or `403` instead of redirecting to login

This capability is intentionally generic. It is useful for BFF-style hosts, server-proxy architectures, and any application that wants to expose downstream APIs through a cookie-authenticated OIDC host without re-implementing proxy routing.

Example:

```json
{
  "Recrovit": {
    "OpenIdConnect": {
      "DownstreamApis": {
        "UserInfoApi": {
          "BaseUrl": "https://graph.microsoft.com/",
          "Scopes": [ "openid", "profile", "email", "User.Read" ],
          "RelativePath": "oidc/userinfo"
        }
      }
    }
  }
}
```

With this configuration:

- `GET /downstream/UserInfoApi` forwards to the configured `RelativePath` for `UserInfoApi`
- `GET /downstream/UserInfoApi/some/extra/path?x=1` appends `some/extra/path?x=1` after the configured route prefix
- request bodies are forwarded for the supported HTTP methods, including `POST`, `PUT`, `PATCH`, and `DELETE`

For example, if `BaseUrl` is `https://api.example.com/gateway` and `RelativePath` is `session/check`, the effective downstream root is `https://api.example.com/gateway/session/check`. Proxy route suffixes are appended under that root, and traversal-style inputs that would resolve outside it are rejected before any outbound request is created.

### Downstream Proxy GET Browser Protection

The host options include `Recrovit:OpenIdConnect:Host:DownstreamProxyGetProtection` for the generic downstream HTTP proxy.

Default behavior:

- protection is enabled by default
- only HTTP `GET` proxy requests are checked
- WebSocket proxy handshakes are not changed by this policy
- `Sec-Fetch-Site` is the primary signal
- when Fetch Metadata headers are unavailable, the host can fall back to a same-origin `Origin` header or to a configured custom request header

Recommended frontend behavior for compatibility paths:

- for browser-based same-origin calls, let the browser send `Sec-Fetch-Site` naturally
- for older clients that do not send Fetch Metadata, send a same-origin `Origin` header when possible
- if neither header is available, configure a custom header such as `X-Recrovit-Proxy-Intent` and send the expected value from the trusted frontend

Example:

```json
{
  "Recrovit": {
    "OpenIdConnect": {
      "Host": {
        "DownstreamProxyGetProtection": {
          "Enabled": true,
          "Mode": "FetchMetadataFirst",
          "AllowOriginFallback": true,
          "CustomHeaderName": "X-Recrovit-Proxy-Intent",
          "CustomHeaderValue": "same-site"
        }
      }
    }
  }
}
```

This protection is a browser-request defense for the generic proxy surface. It does not replace endpoint authorization.

### `Recrovit:OpenIdConnect:TokenCache`

Bound to `TokenCacheOptions`.

Key responsibilities:

- cache key prefix for encrypted stored user tokens
- shared HMAC secret for deriving non-reversible session cache identifiers from provider, issuer, subject, and local session metadata
- deployment mode, which declares whether refresh coordination is expected to remain single-instance or span multiple nodes
- refresh skew, which controls how early token refresh starts before access token expiration
- refresh lock lease duration for session-scoped refresh coordination

### `Recrovit:OpenIdConnect:Infrastructure`

Bound to `HostSecurityOptions`.

Key responsibilities:

- enables forwarded header processing when the host is behind a trusted proxy
- defines the trusted reverse proxy IP addresses and networks that may supply forwarded headers
- configures legacy shared file-system persistence for Data Protection keys
- selects the Data Protection startup validation profile

`DataProtectionKeysPath` is an optional path setting, not a separate on/off switch. It is the shared directory used by ASP.NET Core Data Protection to persist encryption keys. Yes, the application writes key files into this directory.

If you set it, the package persists Data Protection keys in that directory. If you omit it, ASP.NET Core falls back to its default key storage behavior for the current environment.

Use it when you need authentication cookies and encrypted token-cache entries to remain readable across restarts or across multiple app instances. In production, this package requires an explicit shared Data Protection key repository, which can come from `DataProtectionKeysPath` or from host-level Data Protection configuration.

In development or simple single-instance local runs, you can usually omit it. In production, treat an explicit shared key repository as required. For new hosts, prefer configuring Data Protection directly through the new callback overload or host-level `services.AddDataProtection()` setup.

`DataProtectionSecurityProfile` defaults to `Standard`. Set it to `Hardened` to require explicit application isolation and key-ring encryption when the host starts in production.

## Minimal Configuration Example

```json
{
  "Recrovit": {
    "OpenIdConnect": {
      "Host": {
        "CookieName": "__Host-Auth",
        "SessionIdleTimeout": "00:20:00",
        "SessionAbsoluteTimeout": "08:00:00",
        "EnableSlidingExpiration": true,
        "EndpointBasePath": "/authentication",
        "RemoteFailureRedirectPath": "/",
        "SessionValidationDownstreamApiName": "SessionValidationApi"
      },
      "Provider": "MainProvider",
      "Providers": {
        "MainProvider": {
          "Authority": "https://idp.example.com",
          "ClientId": "client-id",
          "ClientAuthenticationMethod": "ClientSecretPost",
          "ClientSecret": "client-secret",
          "Scopes": [ "openid", "profile", "offline_access" ],
          "CallbackPath": "/signin-oidc",
          "SignedOutCallbackPath": "/signout-callback-oidc",
          "RemoteSignOutPath": "/signout-oidc",
          "SignedOutRedirectPath": "/",
          "GetClaimsFromUserInfoEndpoint": true,
          "RequireHttpsMetadata": true,
          "DownstreamApis": {
            "SessionValidationApi": {
              "RelativePath": "session/provider-check"
            },
            "LegacyApi": {
              "Disabled": true
            }
          }
        }
      },
      "DownstreamApis": {
        "SessionValidationApi": {
          "BaseUrl": "https://api.example.com",
          "Scopes": [ "api.scope" ],
          "RelativePath": "session/check"
        },
        "LegacyApi": {
          "BaseUrl": "https://legacy.example.com",
          "Scopes": [ "legacy.read" ],
          "RelativePath": "legacy"
        }
      },
      "TokenCache": {
        "CacheKeyPrefix": "oidc-user-token-cache",
        "RefreshBeforeExpirationSeconds": 60
      },
      "Infrastructure": {
        "ForwardedHeadersEnabled": false,
        "DataProtectionKeysPath": "/shared/dpkeys",
        "DataProtectionSecurityProfile": "Standard"
      }
    }
  }
}
```

## Data Protection Configuration

The package uses ASP.NET Core Data Protection for authentication cookies and for encrypting distributed token-cache payloads. Existing applications can keep using `Recrovit:OpenIdConnect:Infrastructure:DataProtectionKeysPath` without code changes.

For new applications, prefer configuring Data Protection explicitly by using either host-level `services.AddDataProtection()` or the `AddOidcAuthenticationInfrastructure(...)` callback overload:

```csharp
using System.IO;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

var keyDirectory = new DirectoryInfo("/shared/dpkeys");

builder.Services.AddOidcAuthenticationInfrastructure(
    builder.Configuration,
    builder.Environment,
    dataProtection => dataProtection
        .SetApplicationName("MyCompany.MyApplication.Production")
        .PersistKeysToFileSystem(keyDirectory));
```

Use the same application name across all instances of the same deployed application. Use different application names for different applications and different environments. The application name improves isolation, but it does not replace the need for separate key repositories when you need strong security separation.

### Single-Instance Or Simple IIS Hosts

For backward-compatible, simple deployments, `DataProtectionKeysPath` remains supported:

```json
{
  "Recrovit": {
    "OpenIdConnect": {
      "Infrastructure": {
        "DataProtectionKeysPath": "C:\\Auth\\dpkeys"
      }
    }
  }
}
```

This is still valid in `Standard` mode. In production, if the key ring is persisted explicitly but no key-ring encryption is configured, the package logs a warning and continues for backward compatibility.

### Multi-Instance Deployments

Multi-instance hosts should use a shared Data Protection key repository and a shared `IDistributedCache` backend. The shared key repository can be configured through `DataProtectionKeysPath`, through the callback overload, or through host-level `services.AddDataProtection()` registration before the OIDC package is added.

### Certificate-Based Key-Ring Encryption

```csharp
using System.IO;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

var keyDirectory = new DirectoryInfo("/shared/dpkeys");
var keyRingCertificate = LoadDataProtectionCertificate();

builder.Services.AddOidcAuthenticationInfrastructure(
    builder.Configuration,
    builder.Environment,
    dataProtection => dataProtection
        .SetApplicationName("MyCompany.MyApplication.Production")
        .PersistKeysToFileSystem(keyDirectory)
        .ProtectKeysWithCertificate(keyRingCertificate));
```

Keep old decryption certificates available during certificate rotation until every active key ring entry that depends on them has aged out or been re-encrypted.

### Windows DPAPI

```csharp
using System.IO;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

var keyDirectory = new DirectoryInfo(@"C:\Auth\dpkeys");

builder.Services.AddOidcAuthenticationInfrastructure(
    builder.Configuration,
    builder.Environment,
    dataProtection => dataProtection
        .SetApplicationName("MyCompany.MyApplication.Production")
        .PersistKeysToFileSystem(keyDirectory)
        .ProtectKeysWithDpapi());
```

### External KMS Or Provider-Specific Storage

The base package does not reference Azure, AWS, Vault, or any other provider SDK. Install the provider-specific ASP.NET Core Data Protection extensions in the host application, then call them from the callback or from host-level Data Protection registration:

```csharp
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

builder.Services.AddOidcAuthenticationInfrastructure(
    builder.Configuration,
    builder.Environment,
    dataProtection => dataProtection
        .SetApplicationName("MyCompany.MyApplication.Production")
        .PersistKeysToExternalStorage(...)
        .ProtectKeysWithExternalKeyManagementSystem(...));
```

### Standard And Hardened Profiles

`Standard` preserves existing behavior:

- `DataProtectionKeysPath` remains supported
- explicit application isolation is recommended but not required
- explicit key-ring encryption is recommended but not required

`Hardened` adds startup validation:

- production requires explicit application isolation through `SetApplicationName(...)`
- production requires key-ring encryption when an explicit repository is configured
- development logs warnings instead of blocking startup

Example:

```json
{
  "Recrovit": {
    "OpenIdConnect": {
      "Infrastructure": {
        "DataProtectionSecurityProfile": "Hardened"
      }
    }
  }
}
```

Use separate certificates for OIDC client authentication and Data Protection key-ring encryption whenever possible. They serve different security purposes and should not share the same private key by default.

## Certificate-Based Client Authentication

The package also supports certificate-based token endpoint authentication by using `private_key_jwt`.

Set `ClientAuthenticationMethod` to `PrivateKeyJwt`, do not configure `ClientSecret`, and configure `ClientCertificate`.
`ClientSecret` is not required for `PrivateKeyJwt`, because the token endpoint client authentication is performed with a signed client assertion instead.
`ClientCertificate` is required for this mode.

If you resolve `OidcDownstreamUserTokenProvider` from DI, the required `IOidcClientAssertionService` is wired automatically.
If you instantiate `OidcDownstreamUserTokenProvider` directly, use the public constructor overload that accepts `IOidcClientAssertionService`; `PrivateKeyJwt` refresh token exchange requires that service and fails without it.

### PFX File Example

```json
{
  "Recrovit": {
    "OpenIdConnect": {
      "Provider": "MainProvider",
      "Providers": {
        "MainProvider": {
          "Authority": "https://idp.example.com",
          "ClientId": "client-id",
          "ClientAuthenticationMethod": "PrivateKeyJwt",
          "ClientCertificate": {
            "Source": "File",
            "File": {
              "Path": "/secrets/oidc-client.pfx",
              "Password": "pfx-password"
            }
          },
          "Scopes": [ "openid", "profile", "offline_access" ]
        }
      }
    }
  }
}
```

The `.pfx` file must contain a certificate with its private key. A public-certificate-only file is not sufficient, because the package uses that private key to sign the client assertion.

### Windows Certificate Store Example

Windows hosts can also load the certificate from the Windows Certificate Store.
`ClientCertificate:Source = WindowsStore` is supported only on Windows. On non-Windows hosts, package configuration validation rejects that source.

```json
{
  "Recrovit": {
    "OpenIdConnect": {
      "Provider": "MainProvider",
      "Providers": {
        "MainProvider": {
          "Authority": "https://idp.example.com",
          "ClientId": "client-id",
          "ClientAuthenticationMethod": "PrivateKeyJwt",
          "ClientCertificate": {
            "Source": "WindowsStore",
            "Store": {
              "Thumbprint": "ABCD1234EF567890ABCD1234EF567890ABCD1234",
              "StoreName": "My",
              "StoreLocation": "LocalMachine"
            }
          },
          "Scopes": [ "openid", "profile", "offline_access" ]
        }
      }
    }
  }
}
```

The certificate is loaded lazily on first use, not during startup configuration.
After it is loaded, it is cached in memory for the lifetime of the application process.
If the PFX file or Windows Store certificate changes, the package does not reload it automatically; restart the process so the new certificate can be loaded.

For `private_key_jwt` assertions, the package explicitly sets the JOSE `typ` header to `JWT`. Any certificate-derived key identifier headers such as `kid`, `x5t`, or `x5t#S256` are left to the underlying IdentityModel `X509SigningCredentials` behavior rather than being forced by the package. ECDSA certificate assertions also depend on the underlying IdentityModel/runtime algorithm support; when `ES256` signing is unavailable, the package does not attempt a fallback signature algorithm.

When an external identity provider redirects back to the configured callback path with a handled user-facing failure such as `access_denied`, `login_required`, or a canceled sign-in flow, the package redirects the browser to `Recrovit:OpenIdConnect:Host:RemoteFailureRedirectPath` instead of leaving the user on the raw `/signin-oidc` callback failure.

The `Host` section also owns the local cookie session policy:

- `SessionIdleTimeout` controls the cookie idle timeout window
- `EnableSlidingExpiration` determines whether successful activity renews that idle window
- `SessionAbsoluteTimeout` is a hard session lifetime cap that is not extended by sliding expiration

With the defaults, the local session idles out after 20 minutes of inactivity and cannot live longer than 8 hours total. When the absolute timeout is reached, the package clears the stored token state, signs out the cookie session, and returns the standard reauthentication response.

## Reverse Proxy / Forwarded Headers

The default is to keep `Recrovit:OpenIdConnect:Infrastructure:ForwardedHeadersEnabled` set to `false`. Turn it on only when the host is actually running behind a reverse proxy or load balancer that sets `X-Forwarded-For` and `X-Forwarded-Proto`.

When forwarded headers are enabled, the package accepts them only from trusted proxies defined in:

- `Recrovit:OpenIdConnect:Infrastructure:KnownProxies`
- `Recrovit:OpenIdConnect:Infrastructure:KnownNetworks`

This hardening protects redirect generation, request scheme detection, and client IP resolution from bad or incomplete proxy configuration.

In production, the application intentionally fails at startup if forwarded headers are enabled but neither trusted proxy list is configured.

Example for a containerized or ingress-fronted deployment:

```json
{
  "Recrovit": {
    "OpenIdConnect": {
      "Infrastructure": {
        "ForwardedHeadersEnabled": true,
        "KnownProxies": [ "10.42.0.15" ],
        "KnownNetworks": [ "10.42.0.0/16", "192.168.100.0/24" ],
        "DataProtectionKeysPath": "/shared/dpkeys"
      }
    }
  }
}
```

Use `KnownProxies` for fixed proxy addresses and `KnownNetworks` for ingress or load balancer subnets that can change within a bounded range.

## Built-in Authentication Endpoints

The package maps four reusable endpoints under `OidcAuthenticationOptions.EndpointBasePath`:

- `GET /authentication/login`
- `POST /authentication/logout`
- `GET /authentication/session`
- `GET /authentication/principal`

Behavior summary:

- `login` triggers an OpenID Connect challenge, preserves only safe app-relative return URLs, and optionally forwards a `domain_hint` query parameter to the upstream authorize request.
- `logout` requires a same-origin `POST` with a valid antiforgery token, removes stored tokens for the current authenticated session, clears the local cookie-based session, and signs out from both the cookie and OIDC schemes.
- `session` checks whether the current authenticated session is still usable.
- `principal` returns a minimal JSON snapshot of the current authenticated user when the session is still valid: `isAuthenticated`, `name`, `subjectId`, `issuer`, and `objectId`.

Example login URLs:

- `/authentication/login?returnUrl=%2F`
- `/authentication/login?returnUrl=%2F&domain_hint=login.live.com`

The optional `domain_hint` passthrough is useful for identity providers such as Microsoft Entra ID when the client already knows which home domain or tenant-specific sign-in hint should be applied.

## Calling Logout Safely

The logout endpoint is intentionally `POST`-only because it performs a state-changing operation. Call it from a form post or from client code that sends a valid ASP.NET Core antiforgery token.

Blazor or Razor-based hosts can render a standard logout form:

```cshtml
@inject Microsoft.AspNetCore.Antiforgery.IAntiforgery Antiforgery

@{
    var tokens = Antiforgery.GetAndStoreTokens(HttpContext);
}

<form method="post" action="/authentication/logout">
    <input type="hidden" name="@tokens.FormFieldName" value="@tokens.RequestToken" />
    <input type="hidden" name="returnUrl" value="/" />
    <button type="submit">Sign out</button>
</form>
```

When the host configures an antiforgery header name such as `RequestVerificationToken`, SPA-style clients can fetch an antiforgery token from the host and submit it in that header:

```javascript
const token = await fetch("/antiforgery/token", { credentials: "include" })
  .then(async response => ({
    requestToken: await response.text()
  }));

await fetch("/authentication/logout?returnUrl=%2F", {
  method: "POST",
  credentials: "include",
  headers: {
    RequestVerificationToken: token.requestToken
  }
});
```

## Token and Session Lifecycle

When the OIDC sign-in ticket is received, the package stores the OIDC session token set in an external authenticated session token store through `IDownstreamUserTokenStore`.

The default distributed token store encrypts a single versioned session payload with ASP.NET Core Data Protection before writing it to the cache backend. That payload contains the session refresh token, ID token, and any cached per-API access tokens for the authenticated local session.

After storage, the package removes the tokens from the authentication properties before they remain in the authentication cookie. In practice, this means the host keeps the sign-in cookie for local session state, while session tokens and downstream API access tokens are retained separately and scoped to that specific local authenticated session.

The local cookie session uses an explicit timeout model:

- idle timeout is configured through `OidcAuthenticationOptions.SessionIdleTimeout`
- sliding renewal is configured through `OidcAuthenticationOptions.EnableSlidingExpiration`
- absolute session lifetime is configured through `OidcAuthenticationOptions.SessionAbsoluteTimeout`

The absolute lifetime is stamped into the authenticated session ticket at sign-in time and enforced on later requests and on explicit session validation. This keeps the browser session policy auditable instead of relying on implicit cookie defaults alone.

At runtime:

- if a valid unexpired stored access token exists for the requested downstream API, it is reused
- if the API token is near expiration or missing, the package attempts a refresh-token exchange for that API scope set
- if no stored session token set exists, reauthentication is required
- if no refresh token is available for API token renewal, reauthentication is required
- if the token endpoint fails with a recoverable user-facing auth failure such as `invalid_grant`, reauthentication is required
- if token refresh fails because of server-side or transport issues, the request is treated as a service failure

When the package decides the user must sign in again, it clears the local session and writes:

- HTTP status `401 Unauthorized`
- header `X-Recrovit-Auth: reauth-required`

This behavior is handled through `OidcSessionCleanupService`.

The distributed token cache and refresh coordination are session-scoped, not just user-scoped. Multiple concurrent browser sessions for the same subject therefore keep isolated token state, refresh locks, logout cleanup, and reauthentication behavior.

Refresh persistence is modeled as a versioned compare-and-swap update of the complete session token payload. This prevents an older refresh result from overwriting a newer refresh token when token rotation is enabled.

Cache keys no longer contain raw issuer, subject, or session identifiers. The package derives a stable HMAC-based session fingerprint from that metadata and uses it as the external cache key segment instead.

The built-in `DistributedDownstreamUserTokenStore` and `UserRefreshLockProvider` are intended as safe defaults for development and single-instance hosts. They do not by themselves provide production-safe cross-node compare-and-swap or cross-node refresh lease guarantees.

## Session Validation

The `session` and `principal` endpoints use `OidcAuthenticationOptions.SessionValidationDownstreamApiName` when configured.
The configured value must match a named entry under `DownstreamApis`; it does not enable any built-in UserInfo behavior.

If the option is omitted:

- the package only verifies that the user is authenticated locally
- and that a stored session token set still exists

If the option is configured:

- the package requests a downstream access token for that named API through `IDownstreamUserTokenProvider`
- this allows the session check to validate that the downstream token state is still usable, including refresh behavior
- the check validates token acquisition and refreshability for that configured downstream API, not a mandatory HTTP call to a specific endpoint

If the absolute session timeout has elapsed, or downstream refresh determines that reauthentication is needed, the session is cleared and the reauthentication response is returned. If the refresh path fails because of token endpoint or transport problems, the session endpoint returns `503 Service Unavailable`.

## Accessing Downstream User Tokens

Use `IDownstreamUserTokenProvider` when application code needs an access token for a configured downstream API.

```csharp
public sealed class DownstreamApiCaller(IDownstreamUserTokenProvider tokenProvider)
{
    public Task<string> GetTokenAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        return tokenProvider.GetAccessTokenAsync(user, "SessionValidationApi", cancellationToken);
    }
}
```

Runtime expectations:

- the user must be authenticated
- the named API must exist in `DownstreamApiCatalog`
- the downstream API must define at least one scope

The sign-in request scope list is built automatically as the union of:

- `Provider:Scopes`
- all configured `DownstreamApis[*].Scopes`

The token provider uses:

- `DownstreamApiCatalog` to resolve API definitions
- `OidcProviderOptions` to access client credentials and extra login scopes
- `TokenCacheOptions` to decide when refresh should start

Each downstream API access token is acquired and cached independently. A token requested for one API is not reused for another API unless both API definitions resolve to the same logical API name and scope set.

## Proxying Downstream HTTP and Transport Endpoints

The package also provides reusable downstream proxy infrastructure for hosts that keep browser traffic on the local authenticated origin but forward selected requests to configured downstream APIs.

Use this model when:

- the host owns the cookie-based session
- downstream calls should reuse `DownstreamApiCatalog`
- authenticated users may need bearer-token delegation to the downstream API
- browser-facing transport endpoints such as WebSocket-backed realtime channels must still flow through the host

Responsibility split:

- the consuming host owns route mapping and decides which endpoints should proxy downstream
- this package owns the generic downstream proxy services, bearer-token delegation, proxy endpoint conventions, and transport/WebSocket host capability

Behavior summary:

- HTTP proxy requests can be forwarded with or without a downstream bearer token depending on whether the current user is authenticated
- transport-style endpoints can enable WebSocket support through `UseRecrovitOpenIdConnectProxyTransports()`
- proxy routes should still be marked with `AsProxyEndpoint()` so redirect suppression and proxy-aware status handling continue to work

## API and Proxy Authorization Behavior

The package registers a custom authorization result handler that suppresses redirect-based auth flows for API-style requests.

For matching requests:

- authentication challenges return `401`
- authorization failures return `403`

Redirect suppression applies when:

- the selected endpoint carries explicit redirect-suppression metadata
- the selected endpoint is marked as a proxy endpoint
- the request matches a registered proxy route
- the request path starts with `/api`
- the request `Accept` header prefers JSON, including `application/problem+json`

This makes API and proxy consumers receive status codes instead of browser-oriented login redirects.

## Production Requirements

The package validates key production requirements during startup.

In production:

- a shared distributed cache is required for user token storage
- `AddDistributedMemoryCache` is not sufficient for multi-instance production use
- an explicit shared Data Protection key repository is required
- `HostSecurityOptions.DataProtectionKeysPath` remains supported as a backward-compatible way to configure that repository
- `TokenCacheOptions.CacheKeyHmacSecret` must be shared across all instances
- `TokenCacheOptions.DeploymentMode` defaults to `SingleInstance`
- when `TokenCacheOptions.DeploymentMode` is set to `MultiInstance`, the host must replace both `IOidcSessionRefreshLockProvider` and `IOidcSessionStateStore`
- the replacement refresh lock provider must coordinate one authenticated session across nodes for the whole lease duration
- the replacement session state store must provide atomic cross-node compare-and-swap semantics for the full session aggregate

When `DataProtectionSecurityProfile` is set to `Hardened`, production startup also requires:

- explicit Data Protection application isolation through `SetApplicationName(...)`
- explicit key-ring encryption when the key repository is configured explicitly

`AddRecrovitOpenIdConnectInfrastructure()` registers `AddDistributedMemoryCache()` as a safe default for development and simple single-instance runs. Production hosts should replace that default with a shared `IDistributedCache` backend so encrypted token-cache entries remain available across restarts and across multiple application instances.

If `DeploymentMode` is explicitly set to `MultiInstance` while the default single-node refresh lock or the default distributed token store is still registered, startup fails fast with a configuration error.

The package validates that the effective sign-in scope set is not empty and that each configured downstream API declares a non-empty scope list.

## SQL Server Distributed Cache Example

SQL Server is one reasonable production choice when the host already depends on SQL Server infrastructure and wants a shared cache store for OIDC session tokens and downstream API tokens.

The following example replaces the default in-memory distributed cache with `AddDistributedSqlServerCache(...)` and reads the connection string from configuration:

```csharp
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDistributedSqlServerCache(options =>
{
    options.ConnectionString = builder.Configuration.GetConnectionString("RecrovitAuthCache")
        ?? throw new InvalidOperationException("Connection string 'RecrovitAuthCache' is required.");
    options.SchemaName = "dbo";
    options.TableName = "OidcTokenCache";
});

builder.AddRecrovitOpenIdConnectInfrastructure();
```

Create the SQL cache table before running the host:

```bash
dotnet tool install --global dotnet-sql-cache
dotnet sql-cache create "Server=.;Database=RecrovitAuth;Trusted_Connection=True;TrustServerCertificate=True" dbo OidcTokenCache
```

If your environment uses different naming conventions, database separation rules, or SQL authentication settings, adjust the connection string, schema, and table name to match your production standards.
