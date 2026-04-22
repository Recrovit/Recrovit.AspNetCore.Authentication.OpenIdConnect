# Recrovit.AspNetCore.Authentication.OpenIdConnect
[![NuGet Version](https://img.shields.io/nuget/v/Recrovit.AspNetCore.Authentication.OpenIdConnect)](https://www.nuget.org/packages/Recrovit.AspNetCore.Authentication.OpenIdConnect/)

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
- OIDC client credentials
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
- the host acquires or refreshes the signed-in user's downstream access token through `IDownstreamUserTokenProvider`
- the request is forwarded through the built-in downstream HTTP proxy infrastructure
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

### `Recrovit:OpenIdConnect:TokenCache`

Bound to `TokenCacheOptions`.

Key responsibilities:

- cache key prefix for encrypted stored user tokens
  cache entries are scoped separately for OIDC session tokens and per-API access tokens
- refresh skew, which controls how early token refresh starts before access token expiration

### `Recrovit:OpenIdConnect:Infrastructure`

Bound to `HostSecurityOptions`.

Key responsibilities:

- enables forwarded header processing when the host is behind a trusted proxy
- defines the trusted reverse proxy IP addresses and networks that may supply forwarded headers
- configures a shared file-system location for Data Protection keys

`DataProtectionKeysPath` is an optional path setting, not a separate on/off switch. It is the shared directory used by ASP.NET Core Data Protection to persist encryption keys. Yes, the application writes key files into this directory.

If you set it, the package persists Data Protection keys in that directory. If you omit it, ASP.NET Core falls back to its default key storage behavior for the current environment.

Use it when you need authentication cookies and encrypted token-cache entries to remain readable across restarts or across multiple app instances. In production, this package requires `DataProtectionKeysPath` to be configured so all instances can decrypt the same protected data consistently.

In development or simple single-instance local runs, you can usually omit it. In production, treat it as required and point it to a persistent shared location such as a mounted volume or network share.

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
          "ClientSecret": "client-secret",
          "Scopes": [ "openid", "profile", "offline_access" ],
          "CallbackPath": "/signin-oidc",
          "SignedOutCallbackPath": "/signout-callback-oidc",
          "RemoteSignOutPath": "/signout-oidc",
          "SignedOutRedirectPath": "/",
          "GetClaimsFromUserInfoEndpoint": true,
          "RequireHttpsMetadata": true
        }
      },
      "DownstreamApis": {
        "SessionValidationApi": {
          "BaseUrl": "https://api.example.com",
          "Scopes": [ "api.scope" ],
          "RelativePath": "session/check"
        }
      },
      "TokenCache": {
        "CacheKeyPrefix": "oidc-user-token-cache",
        "RefreshBeforeExpirationSeconds": 60
      },
      "Infrastructure": {
        "ForwardedHeadersEnabled": false,
        "DataProtectionKeysPath": "/shared/dpkeys"
      }
    }
  }
}
```

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

The default distributed token store encrypts the cached refresh token, ID token, and per-API access token payloads with ASP.NET Core Data Protection before writing them to the cache backend.

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
- `HostSecurityOptions.DataProtectionKeysPath` must be configured so Data Protection keys are shared

`AddRecrovitOpenIdConnectInfrastructure()` registers `AddDistributedMemoryCache()` as a safe default for development and simple single-instance runs. Production hosts should replace that default with a shared `IDistributedCache` backend so encrypted token-cache entries remain available across restarts and across multiple application instances.

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
