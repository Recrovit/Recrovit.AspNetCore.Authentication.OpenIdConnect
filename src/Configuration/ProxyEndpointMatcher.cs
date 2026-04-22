using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Template;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Matches incoming requests against endpoints marked as proxy endpoints.
/// </summary>
public sealed class ProxyEndpointMatcher(IEnumerable<EndpointDataSource> endpointDataSources)
{
    private readonly object _syncRoot = new();
    private ProxyRouteMatcher[]? _proxyRouteMatchers;

    /// <summary>
    /// Determines whether the specified request targets a registered proxy endpoint.
    /// </summary>
    /// <param name="request">The HTTP request to evaluate.</param>
    /// <returns><see langword="true"/> when the request matches a registered proxy endpoint; otherwise, <see langword="false"/>.</returns>
    public bool IsProxyRequest(HttpRequest request)
    {
        if (!request.Path.HasValue)
        {
            return false;
        }

        foreach (var matcher in GetProxyRouteMatchers())
        {
            if (matcher.IsMatch(request.Path))
            {
                return true;
            }
        }

        return false;
    }

    private ProxyRouteMatcher[] GetProxyRouteMatchers()
    {
        if (_proxyRouteMatchers is not null)
        {
            return _proxyRouteMatchers;
        }

        lock (_syncRoot)
        {
            return _proxyRouteMatchers ??= BuildProxyRouteMatchers();
        }
    }

    private ProxyRouteMatcher[] BuildProxyRouteMatchers()
    {
        return endpointDataSources
            .SelectMany(dataSource => dataSource.Endpoints)
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.Metadata.GetMetadata<ProxyEndpointMetadata>() is not null)
            .Select(ProxyRouteMatcher.Create)
            .OfType<ProxyRouteMatcher>()
            .ToArray();
    }

    private sealed class ProxyRouteMatcher(TemplateMatcher templateMatcher)
    {
        public bool IsMatch(PathString path) => templateMatcher.TryMatch(path, new RouteValueDictionary());

        public static ProxyRouteMatcher? Create(RouteEndpoint endpoint)
        {
            var routePattern = endpoint.RoutePattern.RawText;
            if (string.IsNullOrWhiteSpace(routePattern))
            {
                return null;
            }

            return new ProxyRouteMatcher(new TemplateMatcher(TemplateParser.Parse(routePattern), new RouteValueDictionary()));
        }
    }
}
