using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Describes the certificate source used for certificate-based client authentication.
/// </summary>
public sealed class OidcClientCertificateOptions
{
    /// <summary>
    /// Gets the configured certificate source.
    /// </summary>
    public OidcClientCertificateSource Source { get; init; } = OidcClientCertificateSource.File;

    /// <summary>
    /// Gets the file-based certificate settings.
    /// </summary>
    public OidcClientCertificateFileOptions? File { get; init; }

    /// <summary>
    /// Gets the Windows Certificate Store-based settings.
    /// </summary>
    public OidcClientCertificateStoreOptions? Store { get; init; }
}

/// <summary>
/// Supported certificate sources for certificate-based client authentication.
/// </summary>
public enum OidcClientCertificateSource
{
    /// <summary>
    /// Loads the certificate from a PFX file.
    /// </summary>
    File = 0,

    /// <summary>
    /// Loads the certificate from the Windows Certificate Store.
    /// </summary>
    WindowsStore = 1
}

/// <summary>
/// File-based certificate settings.
/// </summary>
public sealed class OidcClientCertificateFileOptions
{
    /// <summary>
    /// Gets the certificate path.
    /// </summary>
    [Required]
    public string Path { get; init; } = string.Empty;

    /// <summary>
    /// Gets the optional certificate password.
    /// </summary>
    public string? Password { get; init; }
}

/// <summary>
/// Windows Certificate Store-based certificate settings.
/// </summary>
public sealed class OidcClientCertificateStoreOptions
{
    /// <summary>
    /// Gets the certificate thumbprint used for lookup.
    /// </summary>
    [Required]
    public string Thumbprint { get; init; } = string.Empty;

    /// <summary>
    /// Gets the Windows certificate store name.
    /// </summary>
    public StoreName StoreName { get; init; } = StoreName.My;

    /// <summary>
    /// Gets the Windows certificate store location.
    /// </summary>
    public StoreLocation StoreLocation { get; init; } = StoreLocation.LocalMachine;
}
