using System.ComponentModel.DataAnnotations;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Host-facing options for the reusable OIDC infrastructure.
/// </summary>
public sealed class OidcAuthenticationOptions
{
    /// <summary>
    /// Configuration section name.
    /// </summary>
    public const string SectionName = "Host";

    /// <summary>
    /// Gets the authentication cookie name.
    /// </summary>
    [Required]
    public string CookieName { get; init; } = "__Host-Auth";

    /// <summary>
    /// Gets the idle timeout applied to the local authentication cookie.
    /// </summary>
    public TimeSpan SessionIdleTimeout { get; init; } = TimeSpan.FromMinutes(20);

    /// <summary>
    /// Gets the absolute maximum lifetime of a local authenticated session.
    /// </summary>
    public TimeSpan SessionAbsoluteTimeout { get; init; } = TimeSpan.FromHours(8);

    /// <summary>
    /// Gets a value indicating whether the local authentication cookie should slide within the idle timeout window.
    /// </summary>
    public bool EnableSlidingExpiration { get; init; } = true;

    /// <summary>
    /// Gets the base route used for login and logout endpoints.
    /// </summary>
    [Required]
    public string EndpointBasePath { get; init; } = "/authentication";

    /// <summary>
    /// Gets the optional downstream API name used to validate whether the current session is still usable.
    /// When omitted, the session endpoint only verifies the local authenticated session and token-store state.
    /// </summary>
    public string? SessionValidationDownstreamApiName { get; init; }

    /// <summary>
    /// Gets the application-relative path used when an OIDC remote callback returns with a handled user-facing failure.
    /// </summary>
    public string RemoteFailureRedirectPath { get; init; } = "/";

    /// <summary>
    /// Gets the protection policy applied to cookie-authenticated downstream proxy requests.
    /// </summary>
    [Required]
    public DownstreamProxyRequestProtectionOptions DownstreamProxyRequestProtection { get; init; } = new();
}

/// <summary>
/// Defines the host-facing protection policy for cookie-authenticated downstream proxy requests.
/// </summary>
public sealed class DownstreamProxyRequestProtectionOptions
{
    /// <summary>
    /// Gets the primary evaluation strategy used for downstream proxy request protection.
    /// </summary>
    public ProxyRequestProtectionMode Mode { get; init; } = ProxyRequestProtectionMode.FetchMetadataFirst;

    /// <summary>
    /// Gets a value indicating whether <c>Sec-Fetch-Site: same-site</c> is accepted for HTTP requests.
    /// </summary>
    public bool AllowSameSite { get; init; }

    /// <summary>
    /// Gets the optional request header name accepted as an explicit compatibility signal when browser metadata headers are unavailable.
    /// </summary>
    public string? CustomHeaderName { get; init; }

    /// <summary>
    /// Gets the optional request header value expected for <see cref="CustomHeaderName"/>.
    /// </summary>
    public string? CustomHeaderValue { get; init; }

    /// <summary>
    /// Gets the explicitly trusted origins that may satisfy the HTTP origin fallback check.
    /// </summary>
    public string[] AllowedHttpOrigins { get; init; } = [];

    /// <summary>
    /// Gets the explicitly trusted origins that may initiate WebSocket proxy handshakes.
    /// </summary>
    public string[] AllowedWebSocketOrigins { get; init; } = [];

    /// <summary>
    /// Gets a value indicating whether WebSocket requests without an <c>Origin</c> header are accepted.
    /// </summary>
    public bool AllowMissingWebSocketOrigin { get; init; }
}

/// <summary>
/// Defines the supported protection modes for downstream proxy requests.
/// </summary>
public enum ProxyRequestProtectionMode
{
    /// <summary>
    /// Uses <c>Sec-Fetch-Site</c> as the primary request signal and falls back to origin or a configured custom header when Fetch Metadata headers are unavailable.
    /// </summary>
    FetchMetadataFirst = 0
}
