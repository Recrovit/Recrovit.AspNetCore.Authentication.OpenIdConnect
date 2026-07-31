using Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;

/// <summary>
/// Configures downstream proxy endpoint behavior that is fixed at mapping time.
/// </summary>
public sealed class DownstreamProxyEndpointOptions
{
    private readonly Dictionary<string, DownstreamProxyEndpointApiOptions> apis = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets the per-API endpoint configuration builder.
    /// </summary>
    /// <param name="downstreamApiName">The configured downstream API name.</param>
    /// <returns>The per-API configuration builder.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="downstreamApiName"/> is empty.</exception>
    public DownstreamProxyEndpointApiOptions ForApi(string downstreamApiName)
    {
        if (string.IsNullOrWhiteSpace(downstreamApiName))
        {
            throw new ArgumentException("The downstream API name must not be empty.", nameof(downstreamApiName));
        }

        if (!apis.TryGetValue(downstreamApiName, out var apiOptions))
        {
            apiOptions = new DownstreamProxyEndpointApiOptions(downstreamApiName);
            apis[downstreamApiName] = apiOptions;
        }

        return apiOptions;
    }

    internal DownstreamProxyEndpointMetadata Build(DownstreamApiCatalog downstreamApiCatalog, string routePrefix)
    {
        var metadata = new Dictionary<string, DownstreamProxyEndpointApiMetadata>(StringComparer.OrdinalIgnoreCase);

        foreach (var (apiName, apiOptions) in apis)
        {
            if (!downstreamApiCatalog.Apis.ContainsKey(apiName))
            {
                throw new InvalidOperationException($"The downstream API '{apiName}' is not configured.");
            }

            metadata[apiName] = apiOptions.Build();
        }

        return new DownstreamProxyEndpointMetadata(routePrefix, metadata);
    }
}

/// <summary>
/// Configures immutable per-API claim header forwarding rules for mapped downstream proxy endpoints.
/// </summary>
public sealed class DownstreamProxyEndpointApiOptions
{
    private readonly string downstreamApiName;
    private readonly List<DownstreamProxyClaimHeaderMapping> claimHeaderMappings = [];

    internal DownstreamProxyEndpointApiOptions(string downstreamApiName)
    {
        this.downstreamApiName = downstreamApiName;
    }

    /// <summary>
    /// Forwards the first available claim value from the specified claim types into a protected outbound header.
    /// </summary>
    public DownstreamProxyEndpointApiOptions ForwardFirstClaimHeader(string headerName, params string[] claimTypes)
    {
        claimHeaderMappings.Add(DownstreamProxyClaimHeaderMapping.CreateSingleValue(headerName, claimTypes));
        return this;
    }

    /// <summary>
    /// Forwards all distinct non-empty claim values from the specified claim types into a protected outbound header.
    /// </summary>
    public DownstreamProxyEndpointApiOptions ForwardClaimValuesHeader(string headerName, params string[] claimTypes)
    {
        claimHeaderMappings.Add(DownstreamProxyClaimHeaderMapping.CreateMultiValue(headerName, claimTypes));
        return this;
    }

    internal DownstreamProxyEndpointApiMetadata Build()
    {
        var usedHeaderNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var finalizedMappings = new List<DownstreamProxyClaimHeaderMapping>(claimHeaderMappings.Count);

        foreach (var mapping in claimHeaderMappings)
        {
            DownstreamProxyHeaderPolicy.ValidateGeneratedRequestHeaderName(mapping.HeaderName, $"{downstreamApiName}:{mapping.HeaderName}");

            if (!usedHeaderNames.Add(mapping.HeaderName))
            {
                throw new InvalidOperationException(
                    $"The downstream proxy endpoint configuration for API '{downstreamApiName}' defines duplicate protected claim header '{mapping.HeaderName}'.");
            }

            finalizedMappings.Add(mapping);
        }

        return new DownstreamProxyEndpointApiMetadata(finalizedMappings);
    }
}

internal sealed class DownstreamProxyEndpointMetadata
{
    public DownstreamProxyEndpointMetadata(
        string routePrefix,
        IReadOnlyDictionary<string, DownstreamProxyEndpointApiMetadata> apis)
    {
        RoutePrefix = routePrefix;
        Apis = apis;
    }

    public string RoutePrefix { get; }

    public IReadOnlyDictionary<string, DownstreamProxyEndpointApiMetadata> Apis { get; }

    public DownstreamProxyEndpointApiMetadata GetApiMetadata(string downstreamApiName)
        => Apis.TryGetValue(downstreamApiName, out var metadata)
            ? metadata
            : DownstreamProxyEndpointApiMetadata.Empty;
}

internal sealed class DownstreamProxyEndpointApiMetadata
{
    public static DownstreamProxyEndpointApiMetadata Empty { get; } = new([]);

    public DownstreamProxyEndpointApiMetadata(IReadOnlyList<DownstreamProxyClaimHeaderMapping> claimHeaderMappings)
    {
        ClaimHeaderMappings = claimHeaderMappings;
    }

    public IReadOnlyList<DownstreamProxyClaimHeaderMapping> ClaimHeaderMappings { get; }
}

internal sealed class DownstreamProxyClaimHeaderMapping
{
    private DownstreamProxyClaimHeaderMapping(string headerName, IReadOnlyList<string> claimTypes, bool forwardAllValues)
    {
        HeaderName = headerName;
        ClaimTypes = claimTypes;
        ForwardAllValues = forwardAllValues;
    }

    public string HeaderName { get; }

    public IReadOnlyList<string> ClaimTypes { get; }

    public bool ForwardAllValues { get; }

    public static DownstreamProxyClaimHeaderMapping CreateSingleValue(string headerName, string[] claimTypes)
        => new(headerName, ValidateClaimTypes(headerName, claimTypes), forwardAllValues: false);

    public static DownstreamProxyClaimHeaderMapping CreateMultiValue(string headerName, string[] claimTypes)
        => new(headerName, ValidateClaimTypes(headerName, claimTypes), forwardAllValues: true);

    private static string[] ValidateClaimTypes(string headerName, string[] claimTypes)
    {
        if (string.IsNullOrWhiteSpace(headerName))
        {
            throw new ArgumentException("The header name must not be empty.", nameof(headerName));
        }

        if (claimTypes is null || claimTypes.Length == 0 || claimTypes.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException($"At least one non-empty claim type is required for header '{headerName}'.", nameof(claimTypes));
        }

        return claimTypes;
    }
}
