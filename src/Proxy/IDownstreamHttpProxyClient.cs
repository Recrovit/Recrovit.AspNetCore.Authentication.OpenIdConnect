using Microsoft.Extensions.Primitives;
using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

/// <summary>
/// Sends proxied HTTP requests to a configured downstream API.
/// </summary>
public interface IDownstreamHttpProxyClient
{
    Task<HttpResponseMessage> SendAsync(
        string downstreamApiName,
        HttpMethod method,
        string pathAndQuery,
        ClaimsPrincipal? user,
        HttpContent? content,
        IEnumerable<KeyValuePair<string, StringValues>> headers,
        CancellationToken cancellationToken);
}
