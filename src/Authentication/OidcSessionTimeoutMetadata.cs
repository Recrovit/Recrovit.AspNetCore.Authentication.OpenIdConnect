using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal static class OidcSessionTimeoutMetadata
{
    private const string ExpiredSessionContextItemKey = "Recrovit.OpenIdConnect.ExpiredSession";

    public static void StampSessionLifetime(ClaimsPrincipal principal, OidcAuthenticationOptions options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var identity = GetWritableAuthenticatedIdentity(principal);
        var issuedAtUtc = timeProvider.GetUtcNow();
        var absoluteExpiresAtUtc = issuedAtUtc.Add(options.SessionAbsoluteTimeout);

        ReplaceClaim(identity, OidcAuthenticationConstants.ProviderClaimNames.SessionIssuedAtUtc, issuedAtUtc.ToString("O", CultureInfo.InvariantCulture));
        ReplaceClaim(identity, OidcAuthenticationConstants.ProviderClaimNames.SessionAbsoluteExpiresAtUtc, absoluteExpiresAtUtc.ToString("O", CultureInfo.InvariantCulture));
    }

    public static bool HasAbsoluteSessionExpired(ClaimsPrincipal principal, TimeProvider timeProvider, out DateTimeOffset absoluteExpiresAtUtc)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(timeProvider);

        if (!TryGetAbsoluteExpiryUtc(principal, out absoluteExpiresAtUtc))
        {
            return false;
        }

        return timeProvider.GetUtcNow() > absoluteExpiresAtUtc;
    }

    public static void MarkSessionExpired(HttpContext httpContext, ClaimsPrincipal sessionPrincipal, string reason, DateTimeOffset absoluteExpiresAtUtc)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(sessionPrincipal);

        httpContext.Items[ExpiredSessionContextItemKey] = new ExpiredSessionContext(sessionPrincipal, reason, absoluteExpiresAtUtc);
    }

    public static bool TryGetExpiredSession(HttpContext httpContext, out ExpiredSessionContext expiredSession)
    {
        ArgumentNullException.ThrowIfNull(httpContext);

        if (httpContext.Items.TryGetValue(ExpiredSessionContextItemKey, out var expiredSessionValue) &&
            expiredSessionValue is ExpiredSessionContext typedExpiredSession)
        {
            expiredSession = typedExpiredSession;
            return true;
        }

        expiredSession = default!;
        return false;
    }

    private static bool TryGetAbsoluteExpiryUtc(ClaimsPrincipal principal, out DateTimeOffset absoluteExpiresAtUtc)
    {
        var rawValue = principal.FindFirst(OidcAuthenticationConstants.ProviderClaimNames.SessionAbsoluteExpiresAtUtc)?.Value;
        return DateTimeOffset.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out absoluteExpiresAtUtc);
    }

    private static ClaimsIdentity GetWritableAuthenticatedIdentity(ClaimsPrincipal principal)
    {
        return principal.Identities.FirstOrDefault(static identity => identity.IsAuthenticated)
            ?? throw new InvalidOperationException("The authenticated principal does not contain a writable identity.");
    }

    private static void ReplaceClaim(ClaimsIdentity identity, string claimType, string claimValue)
    {
        foreach (var existingClaim in identity.FindAll(claimType).ToArray())
        {
            identity.RemoveClaim(existingClaim);
        }

        identity.AddClaim(new Claim(claimType, claimValue));
    }

    internal sealed record ExpiredSessionContext(ClaimsPrincipal SessionPrincipal, string Reason, DateTimeOffset AbsoluteExpiresAtUtc);
}
