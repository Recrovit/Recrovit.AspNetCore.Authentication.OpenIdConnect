using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

/// <summary>
/// Proxies transport-style requests such as WebSocket connections to a configured downstream API.
/// </summary>
public interface IDownstreamTransportProxyClient
{
    Task ProxyWebSocketAsync(
        HttpContext context,
        string downstreamApiName,
        string pathAndQuery,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken);
}
