using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal enum OidcRemoteFailureKind
{
    Unknown,
    UserCanceled,
    AccessDenied,
    LoginRequired,
    ProtocolError
}

internal readonly record struct OidcRemoteFailureClassification(
    bool IsHandledRemoteFailure,
    OidcRemoteFailureKind Kind,
    bool ShouldRedirect,
    bool ShouldCleanupCorrelationCookies,
    string? Error = null,
    string? ErrorDescription = null,
    string? ErrorSubcode = null);

internal static class OidcRemoteFailureClassifier
{
    private static readonly string[] CancelIndicators =
    [
        "cancel",
        "canceled",
        "cancelled",
        "user_cancel",
        "user canceled",
        "user cancelled",
        "user aborted",
        "abort"
    ];

    public static async ValueTask<OidcRemoteFailureClassification> ClassifyAsync(
        HttpRequest request,
        PathString callbackPath,
        CancellationToken cancellationToken)
    {
        if (!request.Path.Equals(callbackPath))
        {
            return default;
        }

        var query = request.Query;
        var error = GetValue(query, "error");
        var errorDescription = GetValue(query, "error_description");
        var errorSubcode = GetValue(query, "error_subcode");
        var state = GetValue(query, "state");

        if (request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(cancellationToken);
            error ??= GetValue(form, "error");
            errorDescription ??= GetValue(form, "error_description");
            errorSubcode ??= GetValue(form, "error_subcode");
            state ??= GetValue(form, "state");
        }

        return Classify(hasState: !string.IsNullOrWhiteSpace(state), error, errorDescription, errorSubcode);
    }

    public static OidcRemoteFailureClassification Classify(RemoteFailureContext context)
    {
        var query = context.Request.Query;
        var error = GetValue(query, "error");
        var errorDescription = GetValue(query, "error_description");
        var errorSubcode = GetValue(query, "error_subcode");
        var state = GetValue(query, "state");

        if (TryClassifyFromException(context.Failure, out var classification))
        {
            return classification with
            {
                Error = classification.Error ?? error,
                ErrorDescription = classification.ErrorDescription ?? errorDescription,
                ErrorSubcode = classification.ErrorSubcode ?? errorSubcode,
                ShouldCleanupCorrelationCookies = true
            };
        }

        return Classify(!string.IsNullOrWhiteSpace(state), error, errorDescription, errorSubcode);
    }

    public static string GetSafeRedirectPath(string? path)
    {
        return AuthenticationEndpoints.SanitizeReturnUrl(path);
    }

    public static void DeleteTransientCookies(HttpContext httpContext, OpenIdConnectOptions options)
    {
        var noncePrefix = options.NonceCookie.Name;
        var correlationPrefix = options.CorrelationCookie.Name;

        foreach (var cookie in httpContext.Request.Cookies.Keys)
        {
            if (MatchesPrefix(cookie, noncePrefix) || MatchesPrefix(cookie, correlationPrefix))
            {
                httpContext.Response.Cookies.Delete(cookie, new CookieOptions
                {
                    Path = "/",
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.None
                });
            }
        }
    }

    private static OidcRemoteFailureClassification Classify(
        bool hasState,
        string? error,
        string? errorDescription,
        string? errorSubcode)
    {
        if (string.IsNullOrWhiteSpace(error) &&
            string.IsNullOrWhiteSpace(errorDescription) &&
            string.IsNullOrWhiteSpace(errorSubcode))
        {
            return default;
        }

        var normalizedError = Normalize(error);
        var normalizedDescription = Normalize(errorDescription);
        var normalizedSubcode = Normalize(errorSubcode);
        var containsCancelIndicator = ContainsIndicator(normalizedDescription) || ContainsIndicator(normalizedSubcode);

        if (normalizedError is "access_denied")
        {
            return CreateHandledClassification(
                containsCancelIndicator ? OidcRemoteFailureKind.UserCanceled : OidcRemoteFailureKind.AccessDenied,
                error,
                errorDescription,
                errorSubcode,
                shouldCleanupCorrelationCookies: !hasState);
        }

        if (normalizedError is "login_required")
        {
            return CreateHandledClassification(
                OidcRemoteFailureKind.LoginRequired,
                error,
                errorDescription,
                errorSubcode,
                shouldCleanupCorrelationCookies: !hasState);
        }

        if (!hasState && containsCancelIndicator)
        {
            return CreateHandledClassification(
                OidcRemoteFailureKind.UserCanceled,
                error,
                errorDescription,
                errorSubcode,
                shouldCleanupCorrelationCookies: true);
        }

        return new OidcRemoteFailureClassification(
            IsHandledRemoteFailure: false,
            Kind: OidcRemoteFailureKind.ProtocolError,
            ShouldRedirect: false,
            ShouldCleanupCorrelationCookies: false,
            Error: error,
            ErrorDescription: errorDescription,
            ErrorSubcode: errorSubcode);
    }

    private static OidcRemoteFailureClassification CreateHandledClassification(
        OidcRemoteFailureKind kind,
        string? error,
        string? errorDescription,
        string? errorSubcode,
        bool shouldCleanupCorrelationCookies)
    {
        return new OidcRemoteFailureClassification(
            IsHandledRemoteFailure: true,
            Kind: kind,
            ShouldRedirect: true,
            ShouldCleanupCorrelationCookies: shouldCleanupCorrelationCookies,
            Error: error,
            ErrorDescription: errorDescription,
            ErrorSubcode: errorSubcode);
    }

    private static bool TryClassifyFromException(Exception? exception, out OidcRemoteFailureClassification classification)
    {
        if (exception is null)
        {
            classification = default;
            return false;
        }

        var message = Normalize(exception.Message);
        if (string.IsNullOrWhiteSpace(message))
        {
            classification = default;
            return false;
        }

        if (message.Contains("access_denied", StringComparison.Ordinal))
        {
            classification = CreateHandledClassification(
                ContainsIndicator(message) ? OidcRemoteFailureKind.UserCanceled : OidcRemoteFailureKind.AccessDenied,
                error: "access_denied",
                errorDescription: exception.Message,
                errorSubcode: null,
                shouldCleanupCorrelationCookies: true);
            return true;
        }

        if (message.Contains("login_required", StringComparison.Ordinal))
        {
            classification = CreateHandledClassification(
                OidcRemoteFailureKind.LoginRequired,
                error: "login_required",
                errorDescription: exception.Message,
                errorSubcode: null,
                shouldCleanupCorrelationCookies: true);
            return true;
        }

        if (ContainsIndicator(message))
        {
            classification = CreateHandledClassification(
                OidcRemoteFailureKind.UserCanceled,
                error: null,
                errorDescription: exception.Message,
                errorSubcode: null,
                shouldCleanupCorrelationCookies: true);
            return true;
        }

        classification = default;
        return false;
    }

    private static bool ContainsIndicator(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return CancelIndicators.Any(indicator => value.Contains(indicator, StringComparison.Ordinal));
    }

    private static bool MatchesPrefix(string cookieName, string? prefix)
    {
        return !string.IsNullOrWhiteSpace(prefix) &&
            cookieName.StartsWith(prefix, StringComparison.Ordinal);
    }

    private static string? GetValue(IQueryCollection query, string key)
    {
        return query.TryGetValue(key, out var value) ? value.ToString() : null;
    }

    private static string? GetValue(IFormCollection form, string key)
    {
        return form.TryGetValue(key, out var value) ? value.ToString() : null;
    }

    private static string? Normalize(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : Uri.UnescapeDataString(value).Trim().ToLowerInvariant();
    }
}
