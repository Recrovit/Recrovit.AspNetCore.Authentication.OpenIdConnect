namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

/// <summary>
/// Indicates that a proxy path is not safe to resolve against the configured downstream origin.
/// </summary>
internal sealed class InvalidDownstreamProxyPathException(string message) : Exception(message)
{
}
