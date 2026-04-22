using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Logging;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Diagnostics;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

/// <summary>
/// Uses configured downstream API definitions to proxy HTTP requests and attach user access tokens when available.
/// </summary>
public sealed class DownstreamHttpProxyClient(
    ILogger<DownstreamHttpProxyClient> logger,
    HttpClient httpClient,
    IDownstreamUserTokenProvider tokenProvider,
    DownstreamApiCatalog downstreamApiCatalog) : IDownstreamHttpProxyClient
{
    public async Task<HttpResponseMessage> SendAsync(
        string downstreamApiName,
        HttpMethod method,
        string pathAndQuery,
        ClaimsPrincipal? user,
        HttpContent? content,
        IEnumerable<KeyValuePair<string, StringValues>> headers,
        CancellationToken cancellationToken)
    {
        var downstreamApi = downstreamApiCatalog.GetRequired(downstreamApiName);
        var downstreamUri = DownstreamProxyUtilities.CreateDownstreamUri(downstreamApi, pathAndQuery);
        var downstreamLogValue = DownstreamProxyUtilities.FormatDownstreamUriForLogging(downstreamUri);
        using var request = new HttpRequestMessage(method, downstreamUri)
        {
            Content = content
        };

        var accessToken = await DownstreamProxyUtilities.TryGetAccessTokenAsync(tokenProvider, user, downstreamApiName, cancellationToken);
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        DownstreamProxyUtilities.ForwardHeaders(headers, request.Headers, request.Content?.Headers);

        logger.LogInformation(
            "Proxying downstream HTTP request to {DownstreamUri} for API {DownstreamApiName}. Method={Method}, AuthenticatedUser={IsAuthenticated}",
            downstreamLogValue,
            downstreamApiName,
            method,
            user?.Identity?.IsAuthenticated == true);

        logger.LogDebug(
            "Downstream HTTP proxy authorization applied for {DownstreamUri}. DownstreamApiName={DownstreamApiName}, HasBearerToken={HasBearerToken}",
            downstreamLogValue,
            downstreamApiName,
            !string.IsNullOrWhiteSpace(accessToken));

        logger.LogDebug(
            "Downstream HTTP proxy request details for {DownstreamUri}. ForwardedHeaders={HeaderNames}",
            downstreamLogValue,
            string.Join(", ", request.Headers.Select(static h => h.Key).Concat(request.Content?.Headers.Select(static h => h.Key) ?? [])));

        var stopwatch = Stopwatch.StartNew();
        try
        {
            var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            stopwatch.Stop();

            logger.LogInformation(
                "Received downstream HTTP proxy response from {DownstreamUri}. StatusCode={StatusCode}, DurationMs={DurationMs}",
                downstreamLogValue,
                (int)response.StatusCode,
                stopwatch.ElapsedMilliseconds);

            logger.LogDebug(
                "Downstream HTTP proxy response details from {DownstreamUri}. ResponseHeaders={HeaderNames}",
                downstreamLogValue,
                string.Join(", ", response.Headers.Select(static h => h.Key).Concat(response.Content.Headers.Select(static h => h.Key))));

            return response;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            stopwatch.Stop();
            logger.LogError(
                ex,
                "Downstream HTTP proxy request failed for {DownstreamUri}. DownstreamApiName={DownstreamApiName}, DurationMs={DurationMs}",
                downstreamLogValue,
                downstreamApiName,
                stopwatch.ElapsedMilliseconds);
            throw;
        }
    }
}
