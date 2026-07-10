using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;
using Xunit;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Authentication;

public sealed class OidcPrivateKeyJwtClientAssertionServiceTests
{
    private const string TokenEndpoint = "https://idp.example.com/connect/token";

    [Fact]
    public void CreateClientAssertion_WithRsaCertificate_UsesExpectedTypAndMatchesPresentCertificateDerivedHeaders()
    {
        using var certificate = TestCertificates.CreateTemporaryPfx();
        using var serviceProvider = CreateServiceProvider(certificate);

        var service = serviceProvider.GetRequiredService<IOidcClientAssertionService>();

        var assertion = service.CreateClientAssertion(TokenEndpoint);
        var token = new JsonWebToken(assertion);

        Assert.True(token.TryGetHeaderValue<object>(JwtHeaderParameterNames.Typ, out var typ));
        Assert.Equal("JWT", Assert.IsType<string>(typ));
        Assert.Equal(SecurityAlgorithms.RsaSha256, token.Alg);

        AssertPresentCertificateDerivedHeadersMatchIdentityModelBehavior(token, certificate.Certificate);
    }

    [Fact]
    public void CreateClientAssertion_WithEcdsaCertificate_UsesExpectedTypAndMatchesPresentCertificateDerivedHeaders()
    {
        SkipIfEcdsaCertificateAssertionsAreUnsupported();

        using var certificate = TestCertificates.CreateTemporaryEcdsaPfx();
        using var serviceProvider = CreateServiceProvider(certificate);

        var service = serviceProvider.GetRequiredService<IOidcClientAssertionService>();

        var assertion = service.CreateClientAssertion(TokenEndpoint);
        var token = new JsonWebToken(assertion);

        Assert.True(token.TryGetHeaderValue<object>(JwtHeaderParameterNames.Typ, out var typ));
        Assert.Equal("JWT", Assert.IsType<string>(typ));
        Assert.Equal(SecurityAlgorithms.EcdsaSha256, token.Alg);

        AssertPresentCertificateDerivedHeadersMatchIdentityModelBehavior(token, certificate.Certificate);
    }

    private static ServiceProvider CreateServiceProvider(TemporaryPfxCertificate certificate)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOidcAuthenticationInfrastructure(TestConfiguration.Build(new Dictionary<string, string?>
        {
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:ClientAuthenticationMethod"] = "PrivateKeyJwt",
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:ClientSecret"] = null,
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:ClientCertificate:Source"] = "File",
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:ClientCertificate:File:Path"] = certificate.Path,
            [$"{TestConfiguration.RootSectionName}:Providers:Duende:ClientCertificate:File:Password"] = certificate.Password
        }), new FakeWebHostEnvironment());

        return services.BuildServiceProvider();
    }

    private static void AssertPresentCertificateDerivedHeadersMatchIdentityModelBehavior(JsonWebToken token, X509Certificate2 certificate)
    {
        var signingCredentials = new X509SigningCredentials(certificate);
        AssertHeaderValue(token, JwtHeaderParameterNames.Kid, expectedValue: signingCredentials.Key.KeyId);
        AssertHeaderValue(token, JwtHeaderParameterNames.X5t, expectedValue: Base64UrlEncoder.Encode(certificate.GetCertHash()));
        AssertHeaderValue(token, "x5t#S256", expectedValue: Base64UrlEncoder.Encode(SHA256.HashData(certificate.RawData)));
    }

    private static void SkipIfEcdsaCertificateAssertionsAreUnsupported()
    {
        try
        {
            using var certificate = TestCertificates.CreateTemporaryEcdsaPfx();
            using var serviceProvider = CreateServiceProvider(certificate);

            var service = serviceProvider.GetRequiredService<IOidcClientAssertionService>();
            var assertion = service.CreateClientAssertion(TokenEndpoint);
            var token = new JsonWebToken(assertion);

            _ = token.Alg;
        }
        catch (PlatformNotSupportedException ex)
        {
            Assert.SkipWhen(true, $"ECDSA certificate assertions are not supported on this platform: {ex.Message}");
        }
        catch (CryptographicException ex)
        {
            Assert.SkipWhen(true, $"ECDSA certificate assertions could not be created on this platform: {ex.Message}");
        }
        catch (NotSupportedException ex)
        {
            Assert.SkipWhen(true, $"ECDSA certificate assertions are not supported by the current IdentityModel/runtime stack: {ex.Message}");
        }
    }

    private static void AssertHeaderValue(JsonWebToken token, string headerName, string? expectedValue)
    {
        var hasHeader = token.TryGetHeaderValue<object>(headerName, out var actualValue);

        if (!hasHeader)
        {
            // These certificate-derived headers are produced by IdentityModel when present,
            // but the package does not require them to be emitted.
            return;
        }

        Assert.Equal(expectedValue, Assert.IsType<string>(actualValue));
    }
}
