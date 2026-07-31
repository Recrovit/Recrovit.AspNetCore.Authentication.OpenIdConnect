namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal readonly record struct UserTokenCacheKeyContext(
    string Provider,
    string Issuer,
    string SubjectId,
    string SessionId)
{
    public string CreateSessionKey()
        => $"{Provider}\n{Issuer}\n{SubjectId}\n{SessionId}";
}
