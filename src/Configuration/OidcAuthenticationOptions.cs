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
}
