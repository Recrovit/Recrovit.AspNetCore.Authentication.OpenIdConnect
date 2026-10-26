# Downstream Proxy Request Protection

Configure browser-request protection for generic downstream HTTP proxies and WebSocket handshakes, or reuse the same policy in a custom proxy integration.

## Configuration

The policy is configured under `Recrovit:OpenIdConnect:Host:DownstreamProxyRequestProtection`. The host's own origin is automatically trusted; additional HTTP and WebSocket origins are configured separately.

```json
{
  "Recrovit": {
    "OpenIdConnect": {
      "Host": {
        "DownstreamProxyRequestProtection": {
          "Mode": "FetchMetadataFirst",
          "AllowSameSite": false,
          "AllowedHttpOrigins": [ "https://app.example.com" ],
          "AllowedWebSocketOrigins": [ "https://app.example.com" ],
          "AllowMissingWebSocketOrigin": false,
          "CustomHeaderName": "X-Recrovit-Proxy-Intent",
          "CustomHeaderValue": "same-site"
        }
      }
    }
  }
}
```

`FetchMetadataFirst` is the supported evaluation mode. Both origin whitelists are empty by default. Omit `CustomHeaderName` and `CustomHeaderValue` when the HTTP compatibility fallback is not needed. The custom header value is a request-intent marker; it does not enable `AllowSameSite` or authenticate the user.

Origin values must be absolute HTTP(S) origins consisting of scheme, host and optional port. Credentials, application paths, query strings and fragments are not accepted. The comparison normalizes host/scheme casing and default ports. The host origin comes from the effective request scheme and authority.

## HTTP evaluation rules

`Sec-Fetch-Site` is evaluated before any fallback:

| Signal | Decision |
| --- | --- |
| `same-origin` | Accepted. If Origin is also supplied, it must match the host origin. A whitelisted foreign Origin cannot override this requirement. |
| `same-site` | Rejected by default. With `AllowSameSite=true`, accepted; a supplied Origin must match the host or `AllowedHttpOrigins`. |
| `cross-site`, `none`, or an unrecognized value | Rejected, including when Origin is whitelisted or a valid custom header is present. |
| Missing `Sec-Fetch-Site` | Evaluate Origin, then the custom-header fallback as described below. |

When Fetch Metadata is absent, a single valid Origin is accepted if it matches the host or `AllowedHttpOrigins`. If Origin is also absent, the configured custom header must contain exactly one value matching `CustomHeaderValue`. Without an accepted signal, the request is rejected.

Empty, multiple or comma-separated Origin/Fetch Metadata values are rejected. A malformed, disallowed or contradictory browser signal is never replaced by a fallback. HTTP policy rejections return 403 before token acquisition or downstream dispatch in the generic proxy.

For same-origin browser clients, allow the browser to send Fetch Metadata normally. Older or server-side HTTP clients can supply the host Origin, or use the explicitly configured custom-header fallback when both browser headers are absent. Restrict any automatically supplied compatibility signal to the intended trusted host destination.

## WebSocket evaluation rules

WebSocket handshakes use Origin validation rather than the HTTP Fetch Metadata/custom-header fallback:

- A single valid Origin must match the host or `AllowedWebSocketOrigins`.
- `AllowedHttpOrigins` does not authorize WebSocket origins.
- Invalid, multiple and `null` origins are rejected.
- Missing Origin is rejected by default. Only `AllowMissingWebSocketOrigin=true` permits it; invalid or `null` values remain rejected.

HTTP negotiate and other HTTP transport requests use the HTTP rules, even when they precede a WebSocket connection. A client using both transports may therefore need acceptance under both policies. Non-browser WebSocket clients should supply the trusted host Origin where possible; opt into missing-origin compatibility only when required.

## Antiforgery validation

Origin evaluation and antiforgery validation are separate steps. In the generic downstream proxy, accepted HTTP methods other than GET, HEAD, OPTIONS and TRACE additionally require a valid antiforgery token. This includes POST, PUT, PATCH and DELETE requests accepted through either a whitelist or the custom-header fallback.

The host frontend must provide a token issuance mechanism and send the token expected by the host's ASP.NET Core antiforgery configuration. A failed antiforgery validation returns 400 without downstream dispatch. WebSocket handshakes do not require an antiforgery token.

An allowed origin or custom request-intent header does not grant user permissions or replace endpoint authorization. These signals defend against browser initiation from an untrusted origin; non-browser clients can supply headers themselves.

## Reusing the evaluator in custom proxies

`AddOidcAuthenticationInfrastructure(...)` registers the public `IDownstreamProxyRequestProtectionEvaluator`. Resolve it from DI and call `Evaluate(HttpContext)` before access-token acquisition, downstream HTTP calls or opening downstream WebSockets. The concrete implementation remains internal; custom integrations reuse its policy rather than implementing a separate Origin algorithm.

The returned `DownstreamProxyRequestProtectionEvaluation` separates the decisions:

| Member | Use |
| --- | --- |
| `IsAllowed` | Whether the request passes the Origin/Fetch Metadata policy. |
| `FailureStatusCode` | Status to return when `IsAllowed` is false. |
| `RequiresAntiforgeryValidation` | Whether the generic proxy must additionally validate an antiforgery token. The evaluator itself does not validate tokens. |
| `RequestType` and `Reason` | Transport and diagnostic context for the evaluation. |

Every endpoint protected through this service must carry `.AsProxyEndpoint()` metadata (`ProxyEndpointMetadata`). **Without that metadata the evaluator returns an allowed result.** A custom proxy should verify the metadata before evaluation and reject its absence, and retain regression coverage for every protected mapping.

The generic proxy checks both `IsAllowed` and `RequiresAntiforgeryValidation`, validating the token when required. A custom integration owns any different antiforgery contract for its endpoints; reusing the origin decision does not change the generic proxy's token requirement.

## Reverse proxies and trust boundaries

Configure trusted forwarded headers before authentication and endpoint execution so that the effective request scheme and authority represent the public host origin. A mismatch between the public URL and the internal listener must be corrected in host/reverse-proxy configuration rather than by broadly accepting missing browser signals.

The whitelists describe origins allowed to initiate requests to the host. They do not select the downstream API destination or change its authentication. A downstream API on a separate origin remains an independent trust boundary.

## Implementation references

- [Policy options](../src/Configuration/OidcAuthenticationOptions.cs)
- [Evaluator and result](../src/Proxy/DownstreamProxyRequestProtectionEvaluator.cs)
- [Generic proxy integration and antiforgery validation](../src/Proxy/DownstreamApiProxyEndpointRouteBuilderExtensions.cs)

See the [README](../README.md#downstream-proxy-request-protection) for host integration.
