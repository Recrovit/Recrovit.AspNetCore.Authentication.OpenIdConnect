using System.Security.Cryptography.X509Certificates;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal interface IOidcClientCertificateLoader
{
    X509Certificate2 GetCertificate();
}
