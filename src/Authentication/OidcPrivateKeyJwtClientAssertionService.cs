using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal sealed class OidcPrivateKeyJwtClientAssertionService(
    IOidcClientCertificateLoader certificateLoader,
    IOptions<OidcProviderOptions> oidcOptions,
    TimeProvider timeProvider) : IOidcClientAssertionService
{
    private static readonly JsonWebTokenHandler TokenHandler = new();

    public string CreateClientAssertion(string tokenEndpoint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenEndpoint);

        var certificate = certificateLoader.GetCertificate();
        var clientId = oidcOptions.Value.ClientId;
        var now = timeProvider.GetUtcNow();
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = tokenEndpoint,
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, clientId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("n"))
            ]),
            NotBefore = now.UtcDateTime,
            Expires = now.AddMinutes(5).UtcDateTime,
            SigningCredentials = CreateSigningCredentials(certificate),
            AdditionalHeaderClaims = CreateHeaderClaims()
        };

        return TokenHandler.CreateToken(descriptor);
    }

    private static SigningCredentials CreateSigningCredentials(X509Certificate2 certificate)
    {
        if (certificate.GetRSAPrivateKey() is not null)
        {
            return new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256);
        }

        if (certificate.GetECDsaPrivateKey() is not null)
        {
            return new X509SigningCredentials(certificate, SecurityAlgorithms.EcdsaSha256);
        }

        throw new InvalidOperationException("The configured client certificate does not expose a supported private key for JWT signing.");
    }

    private static IDictionary<string, object> CreateHeaderClaims()
    {
        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [JwtHeaderParameterNames.Typ] = "JWT"
        };
    }
}
