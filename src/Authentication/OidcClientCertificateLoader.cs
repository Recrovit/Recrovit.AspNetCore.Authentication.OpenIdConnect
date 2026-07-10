using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal sealed class OidcClientCertificateLoader(
    IOptions<OidcProviderOptions> oidcOptions,
    ICertificateStoreReader certificateStoreReader) : IOidcClientCertificateLoader, IDisposable
{
    private readonly object syncLock = new();
    private X509Certificate2? cachedCertificate;

    public X509Certificate2 GetCertificate()
    {
        if (cachedCertificate is not null)
        {
            return cachedCertificate;
        }

        lock (syncLock)
        {
            if (cachedCertificate is not null)
            {
                return cachedCertificate;
            }

            cachedCertificate = LoadCertificate(oidcOptions.Value.ClientCertificate);
            return cachedCertificate;
        }
    }

    public void Dispose()
    {
        cachedCertificate?.Dispose();
    }

    private X509Certificate2 LoadCertificate(OidcClientCertificateOptions? certificateOptions)
    {
        if (certificateOptions is null)
        {
            throw new InvalidOperationException("Certificate-based client authentication requires a configured client certificate.");
        }

        return certificateOptions.Source switch
        {
            OidcClientCertificateSource.File => LoadFromFile(certificateOptions.File),
            OidcClientCertificateSource.WindowsStore => LoadFromWindowsStore(certificateOptions.Store),
            _ => throw new InvalidOperationException($"Unsupported certificate source '{certificateOptions.Source}'.")
        };
    }

    private static X509Certificate2 LoadFromFile(OidcClientCertificateFileOptions? fileOptions)
    {
        if (fileOptions is null || string.IsNullOrWhiteSpace(fileOptions.Path))
        {
            throw new InvalidOperationException("Certificate-based client authentication requires ClientCertificate:File:Path.");
        }

        if (!File.Exists(fileOptions.Path))
        {
            throw new InvalidOperationException($"The configured client certificate file '{fileOptions.Path}' does not exist.");
        }

        return X509CertificateLoader.LoadPkcs12FromFile(
            fileOptions.Path,
            fileOptions.Password,
            X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
    }

    private X509Certificate2 LoadFromWindowsStore(OidcClientCertificateStoreOptions? storeOptions)
    {
        if (storeOptions is null || string.IsNullOrWhiteSpace(storeOptions.Thumbprint))
        {
            throw new InvalidOperationException("Certificate-based client authentication requires ClientCertificate:Store:Thumbprint.");
        }

        var certificates = certificateStoreReader.FindByThumbprint(
            storeOptions.StoreName,
            storeOptions.StoreLocation,
            storeOptions.Thumbprint);
        if (certificates.Count == 0)
        {
            throw new InvalidOperationException(
                $"The configured client certificate thumbprint '{storeOptions.Thumbprint}' was not found in the Windows Certificate Store.");
        }

        if (certificates.Count > 1)
        {
            throw new InvalidOperationException(
                $"The configured client certificate thumbprint '{storeOptions.Thumbprint}' matched multiple certificates in the Windows Certificate Store.");
        }

        return certificates[0];
    }
}
