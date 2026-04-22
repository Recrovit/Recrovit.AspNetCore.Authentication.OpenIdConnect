using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;
using System.Net.WebSockets;
using System.Security.Claims;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

/// <summary>
/// Proxies transport-style requests such as WebSocket connections to configured downstream APIs.
/// </summary>
public sealed class DownstreamTransportProxyClient(
    ILogger<DownstreamTransportProxyClient> logger,
    IDownstreamUserTokenProvider tokenProvider,
    DownstreamApiCatalog downstreamApiCatalog) : IDownstreamTransportProxyClient
{
    public async Task ProxyWebSocketAsync(
        HttpContext context,
        string downstreamApiName,
        string pathAndQuery,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            logger.LogWarning(
                "Rejected non-WebSocket transport proxy request for downstream API {DownstreamApiName} and path {PathAndQuery}.",
                downstreamApiName,
                DownstreamProxyUtilities.FormatPathAndQueryForLogging(pathAndQuery));
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var downstreamApi = downstreamApiCatalog.GetRequired(downstreamApiName);
        var downstreamUri = DownstreamProxyUtilities.CreateDownstreamUri(downstreamApi, pathAndQuery, useWebSocketScheme: true);
        var downstreamLogValue = DownstreamProxyUtilities.FormatDownstreamUriForLogging(downstreamUri);
        var accessToken = await DownstreamProxyUtilities.TryGetAccessTokenAsync(tokenProvider, user, downstreamApiName, cancellationToken);

        using var downstreamSocket = new ClientWebSocket();
        foreach (var subProtocol in context.WebSockets.WebSocketRequestedProtocols)
        {
            downstreamSocket.Options.AddSubProtocol(subProtocol);
        }

        DownstreamProxyUtilities.ForwardHeaders(context.Request.Headers, downstreamSocket.Options);

        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            downstreamSocket.Options.SetRequestHeader("Authorization", $"Bearer {accessToken}");
        }

        logger.LogInformation(
            "Opening downstream WebSocket proxy connection to {DownstreamUri} for API {DownstreamApiName}. AuthenticatedUser={IsAuthenticated}, RequestedSubProtocols={SubProtocols}",
            downstreamLogValue,
            downstreamApiName,
            user?.Identity?.IsAuthenticated == true,
            string.Join(", ", context.WebSockets.WebSocketRequestedProtocols));

        try
        {
            await downstreamSocket.ConnectAsync(downstreamUri, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Failed to connect downstream WebSocket proxy to {DownstreamUri} for API {DownstreamApiName}.", downstreamLogValue, downstreamApiName);
            if (!context.Response.HasStarted)
            {
                context.Response.StatusCode = StatusCodes.Status502BadGateway;
            }

            return;
        }

        logger.LogInformation(
            "Connected downstream WebSocket proxy to {DownstreamUri}. DownstreamState={DownstreamState}, NegotiatedSubProtocol={SubProtocol}",
            downstreamLogValue,
            downstreamSocket.State,
            downstreamSocket.SubProtocol ?? "<none>");

        using var upstreamSocket = await context.WebSockets.AcceptWebSocketAsync(downstreamSocket.SubProtocol);
        using var proxyCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var upstreamToDownstream = PumpAsync("upstream->downstream", upstreamSocket, downstreamSocket, proxyCancellation.Token);
        var downstreamToUpstream = PumpAsync("downstream->upstream", downstreamSocket, upstreamSocket, proxyCancellation.Token);

        try
        {
            var completedTask = await Task.WhenAny(upstreamToDownstream, downstreamToUpstream);
            logger.LogInformation(
                "WebSocket proxy pump completed first for {DownstreamUri}. UpstreamState={UpstreamState}, DownstreamState={DownstreamState}",
                downstreamLogValue,
                upstreamSocket.State,
                downstreamSocket.State);
            proxyCancellation.Cancel();
            await completedTask;
            await AwaitIgnoringCancellationAsync(upstreamToDownstream, downstreamToUpstream);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "WebSocket proxy pump failed for {DownstreamUri}. UpstreamState={UpstreamState}, DownstreamState={DownstreamState}", downstreamLogValue, upstreamSocket.State, downstreamSocket.State);
            await TryCloseAsync(upstreamSocket, WebSocketCloseStatus.InternalServerError, "proxy-error", CancellationToken.None);
            await TryCloseAsync(downstreamSocket, WebSocketCloseStatus.InternalServerError, "proxy-error", CancellationToken.None);
        }
        finally
        {
            await TryCloseAsync(upstreamSocket, WebSocketCloseStatus.NormalClosure, "proxy-complete", CancellationToken.None);
            await TryCloseAsync(downstreamSocket, WebSocketCloseStatus.NormalClosure, "proxy-complete", CancellationToken.None);

            AbortIfStillActive(upstreamSocket);
            AbortIfStillActive(downstreamSocket);

            logger.LogInformation(
                "Closed WebSocket proxy connection for {DownstreamUri}. FinalUpstreamState={UpstreamState}, FinalDownstreamState={DownstreamState}",
                downstreamLogValue,
                upstreamSocket.State,
                downstreamSocket.State);
        }
    }

    private async Task PumpAsync(string direction, WebSocket source, WebSocket destination, CancellationToken cancellationToken)
    {
        var buffer = new byte[16 * 1024];

        while (true)
        {
            var result = await source.ReceiveAsync(buffer, cancellationToken);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                logger.LogInformation(
                    "WebSocket proxy received close frame on {Direction}. SourceState={SourceState}, DestinationState={DestinationState}, CloseStatus={CloseStatus}, CloseDescription={CloseDescription}",
                    direction,
                    source.State,
                    destination.State,
                    result.CloseStatus,
                    result.CloseStatusDescription ?? "<none>");
                await CloseOutputAsync(destination, result.CloseStatus, result.CloseStatusDescription, cancellationToken);
                return;
            }

            logger.LogDebug(
                "WebSocket proxy forwarded frame on {Direction}. MessageType={MessageType}, Count={Count}, EndOfMessage={EndOfMessage}, SourceState={SourceState}, DestinationState={DestinationState}",
                direction,
                result.MessageType,
                result.Count,
                result.EndOfMessage,
                source.State,
                destination.State);

            await destination.SendAsync(
                new ArraySegment<byte>(buffer, 0, result.Count),
                result.MessageType,
                result.EndOfMessage,
                cancellationToken);
        }
    }

    private static async Task CloseOutputAsync(WebSocket socket, WebSocketCloseStatus? closeStatus, string? description, CancellationToken cancellationToken)
    {
        if (socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
        {
            await socket.CloseOutputAsync(closeStatus ?? WebSocketCloseStatus.NormalClosure, description, cancellationToken);
        }
    }

    private static async Task TryCloseAsync(WebSocket socket, WebSocketCloseStatus closeStatus, string description, CancellationToken cancellationToken)
    {
        if (socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
        {
            try
            {
                await socket.CloseAsync(closeStatus, description, cancellationToken);
            }
            catch (WebSocketException)
            {
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    private static void AbortIfStillActive(WebSocket socket)
    {
        if (socket.State is not WebSocketState.Closed and not WebSocketState.Aborted and not WebSocketState.None)
        {
            socket.Abort();
        }
    }

    private static async Task AwaitIgnoringCancellationAsync(params Task[] tasks)
    {
        foreach (var task in tasks)
        {
            try
            {
                await task;
            }
            catch (OperationCanceledException)
            {
            }
        }
    }
}
