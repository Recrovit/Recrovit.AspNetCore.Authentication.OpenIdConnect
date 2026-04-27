using System.Security.Cryptography.X509Certificates;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal interface ICertificateStoreReader
{
    IReadOnlyList<X509Certificate2> FindByThumbprint(StoreName storeName, StoreLocation storeLocation, string thumbprint);
}
