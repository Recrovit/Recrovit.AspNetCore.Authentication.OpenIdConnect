using System.Security.Cryptography.X509Certificates;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal sealed class WindowsCertificateStoreReader : ICertificateStoreReader
{
    public IReadOnlyList<X509Certificate2> FindByThumbprint(StoreName storeName, StoreLocation storeLocation, string thumbprint)
    {
        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates
            .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
            .Cast<X509Certificate2>()
            .ToArray();
    }
}
