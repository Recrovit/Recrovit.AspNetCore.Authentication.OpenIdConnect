using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal sealed class UserTokenCacheKeyProtector(IOptions<TokenCacheOptions> tokenCacheOptions)
{
    public string CreateSessionFingerprint(UserTokenCacheKeyContext context)
    {
        var payload = $"{context.Provider}\n{context.Issuer}\n{context.SubjectId}\n{context.SessionId}";
        var secret = tokenCacheOptions.Value.CacheKeyHmacSecret;
        var hash = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexString(hash);
    }
}
