using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Diagnostics;
using Recrovit.AspNetCore.Authentication.OpenIdConnect.Proxy;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Configuration;

/// <summary>
/// Provides service registration extensions for the reusable OIDC authentication infrastructure.
/// </summary>
public static class OidcAuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Registers the generic OIDC authentication infrastructure for an ASP.NET Core host.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configuration">The application configuration used to bind authentication options.</param>
    /// <param name="environment">The current hosting environment.</param>
    /// <returns>The same service collection instance.</returns>
    public static IServiceCollection AddOidcAuthenticationInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration,
        IWebHostEnvironment environment)
    {
        var hostSection = OpenIdConnectConfigurationResolver.GetHostSection(configuration);
        var tokenCacheSection = OpenIdConnectConfigurationResolver.GetTokenCacheSection(configuration);
        var infrastructureSection = OpenIdConnectConfigurationResolver.GetInfrastructureSection(configuration);
        var activeProviderName = OpenIdConnectConfigurationResolver.GetActiveProviderName(configuration);
        var providerSection = OpenIdConnectConfigurationResolver.GetActiveProviderSection(configuration);
        var downstreamApisSection = OpenIdConnectConfigurationResolver.GetDownstreamApisSection(configuration);
        var downstreamApiCatalog = DownstreamApiCatalog.Create(downstreamApisSection);
        var configuredProviderOptions = providerSection.Get<OidcProviderOptions>()
            ?? throw new InvalidOperationException("The OIDC configuration could not be loaded.");
        var scopeResolver = new OidcScopeResolver(configuredProviderOptions.Scopes, downstreamApiCatalog);

        services.AddSingleton<IWebHostEnvironment>(environment);
        services.AddSingleton<IHostEnvironment>(environment);
        services.TryAddSingleton(TimeProvider.System);

        services.AddOptions<OidcProviderOptions>()
            .Bind(providerSection)
            .ValidateDataAnnotations()
            .Validate(
                options => options.Scopes.All(scope => !string.IsNullOrWhiteSpace(scope)),
                $"{providerSection.Path}:Scopes must not contain empty values.")
            .Validate(
                options => options.ClientAuthenticationMethod != OidcClientAuthenticationMethod.ClientSecretPost
                    || !string.IsNullOrWhiteSpace(options.ClientSecret),
                $"{providerSection.Path}:ClientSecret is required when ClientAuthenticationMethod is ClientSecretPost.")
            .Validate(
                options => options.ClientAuthenticationMethod != OidcClientAuthenticationMethod.PrivateKeyJwt
                    || options.ClientCertificate is not null,
                $"{providerSection.Path}:ClientCertificate is required when ClientAuthenticationMethod is PrivateKeyJwt.")
            .Validate(
                options => options.ClientAuthenticationMethod != OidcClientAuthenticationMethod.PrivateKeyJwt
                    || options.ClientCertificate!.Source != OidcClientCertificateSource.File
                    || !string.IsNullOrWhiteSpace(options.ClientCertificate.File?.Path),
                $"{providerSection.Path}:ClientCertificate:File:Path is required when ClientCertificate:Source is File.")
            .Validate(
                options => options.ClientAuthenticationMethod != OidcClientAuthenticationMethod.PrivateKeyJwt
                    || options.ClientCertificate!.Source != OidcClientCertificateSource.WindowsStore
                    || !string.IsNullOrWhiteSpace(options.ClientCertificate.Store?.Thumbprint),
                $"{providerSection.Path}:ClientCertificate:Store:Thumbprint is required when ClientCertificate:Source is WindowsStore.")
            .Validate(
                options => options.ClientAuthenticationMethod != OidcClientAuthenticationMethod.PrivateKeyJwt
                    || options.ClientCertificate!.Source != OidcClientCertificateSource.WindowsStore
                    || OperatingSystem.IsWindows(),
                $"{providerSection.Path}:ClientCertificate:Source 'WindowsStore' is only supported on Windows.")
            .ValidateOnStart();

        services.AddOptions<TokenCacheOptions>()
            .Bind(tokenCacheSection)
            .ValidateDataAnnotations()
            .ValidateOnStart();
        services.AddOptions<ActiveOidcProviderOptions>()
            .Configure(options => options.ProviderName = activeProviderName)
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<OidcAuthenticationOptions>()
            .Bind(hostSection)
            .ValidateDataAnnotations()
            .Validate(
                options => IsValidPath(options.EndpointBasePath),
                $"{hostSection.Path}:EndpointBasePath must be an app-relative path that starts with '/'.")
            .Validate(
                options => IsValidPath(options.RemoteFailureRedirectPath),
                $"{hostSection.Path}:RemoteFailureRedirectPath must be an app-relative path that starts with '/'.")
            .Validate(
                options => options.SessionIdleTimeout > TimeSpan.Zero,
                $"{hostSection.Path}:SessionIdleTimeout must be a positive time span.")
            .Validate(
                options => options.SessionAbsoluteTimeout > TimeSpan.Zero,
                $"{hostSection.Path}:SessionAbsoluteTimeout must be a positive time span.")
            .Validate(
                options => options.SessionAbsoluteTimeout >= options.SessionIdleTimeout,
                $"{hostSection.Path}:SessionAbsoluteTimeout must be greater than or equal to SessionIdleTimeout.")
            .Validate(
                options => string.IsNullOrWhiteSpace(options.SessionValidationDownstreamApiName)
                    || downstreamApiCatalog.Apis.ContainsKey(options.SessionValidationDownstreamApiName),
                $"{hostSection.Path}:SessionValidationDownstreamApiName must reference a configured entry in {downstreamApisSection.Path}.")
            .ValidateOnStart();

        services.AddOptions<HostSecurityOptions>()
            .Bind(infrastructureSection)
            .Validate(
                ForwardedHeadersConfiguration.AreKnownProxiesValid,
                $"Each entry in {ForwardedHeadersConfiguration.KnownProxiesConfigurationPath} must be a valid IP address.")
            .Validate(
                ForwardedHeadersConfiguration.AreKnownNetworksValid,
                $"Each entry in {ForwardedHeadersConfiguration.KnownNetworksConfigurationPath} must be a valid CIDR network.")
            .ValidateOnStart();

        services.AddSingleton(downstreamApiCatalog);
        services.AddSingleton(scopeResolver);
        services.AddSingleton<IUserRefreshLockProvider, UserRefreshLockProvider>();
        services.AddSingleton<ICertificateStoreReader, WindowsCertificateStoreReader>();
        services.AddSingleton<IOidcClientCertificateLoader, OidcClientCertificateLoader>();
        services.AddSingleton<IOidcClientAssertionService, OidcPrivateKeyJwtClientAssertionService>();

        services.AddDistributedMemoryCache();
        services.AddHttpContextAccessor();
        services.AddHttpClient();
        services.AddHttpClient<IDownstreamHttpProxyClient, DownstreamHttpProxyClient>();
        services.AddSingleton<ProxyEndpointMatcher>();
        services.AddScoped<IDownstreamTransportProxyClient, DownstreamTransportProxyClient>();

        services.AddScoped<IDownstreamUserTokenStore, DistributedDownstreamUserTokenStore>();
        services.AddScoped<IDownstreamUserTokenProvider>(serviceProvider => new OidcDownstreamUserTokenProvider(
            serviceProvider.GetRequiredService<IDownstreamUserTokenStore>(),
            serviceProvider.GetRequiredService<IUserRefreshLockProvider>(),
            serviceProvider.GetRequiredService<DownstreamApiCatalog>(),
            serviceProvider.GetRequiredService<OidcScopeResolver>(),
            serviceProvider.GetRequiredService<IOptions<OidcProviderOptions>>(),
            serviceProvider.GetRequiredService<IOptions<ActiveOidcProviderOptions>>(),
            serviceProvider.GetRequiredService<IOptions<TokenCacheOptions>>(),
            serviceProvider.GetRequiredService<ILogger<OidcDownstreamUserTokenProvider>>(),
            serviceProvider.GetRequiredService<IHttpClientFactory>(),
            serviceProvider.GetRequiredService<IWebHostEnvironment>(),
            serviceProvider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>(),
            serviceProvider.GetRequiredService<IOidcClientAssertionService>()));
        services.AddScoped<OidcSessionCleanupService>();

        services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                var hostOptions = hostSection.Get<OidcAuthenticationOptions>()
                    ?? new OidcAuthenticationOptions();

                options.Cookie.Name = hostOptions.CookieName;
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.ExpireTimeSpan = hostOptions.SessionIdleTimeout;
                options.SlidingExpiration = hostOptions.EnableSlidingExpiration;
                options.Events = new CookieAuthenticationEvents
                {
                    OnValidatePrincipal = context =>
                    {
                        var principal = context.Principal;
                        if (principal is null)
                        {
                            return Task.CompletedTask;
                        }

                        var timeProvider = context.HttpContext.RequestServices.GetRequiredService<TimeProvider>();
                        if (!OidcSessionTimeoutMetadata.HasAbsoluteSessionExpired(principal, timeProvider, out var absoluteExpiresAtUtc))
                        {
                            return Task.CompletedTask;
                        }

                        var logger = context.HttpContext.RequestServices
                            .GetRequiredService<ILoggerFactory>()
                            .CreateLogger("Recrovit.AspNetCore.Authentication.OpenIdConnect.SessionTimeout");
                        OidcSessionCleanupLog.SessionAbsoluteTimeoutExpired(
                            logger,
                            context.HttpContext.Request.Path.Value ?? "/",
                            absoluteExpiresAtUtc);

                        OidcSessionTimeoutMetadata.MarkSessionExpired(
                            context.HttpContext,
                            principal,
                            "absolute-timeout-expired",
                            absoluteExpiresAtUtc);
                        context.RejectPrincipal();
                        return Task.CompletedTask;
                    }
                };
            })
            .AddOpenIdConnect(options =>
            {
                var oidcOptions = providerSection.Get<OidcProviderOptions>()
                    ?? throw new InvalidOperationException("The OIDC configuration could not be loaded.");

                options.Authority = oidcOptions.Authority;
                options.ClientId = oidcOptions.ClientId;
                options.ClientSecret = oidcOptions.ClientAuthenticationMethod == OidcClientAuthenticationMethod.ClientSecretPost
                    ? oidcOptions.ClientSecret
                    : null;
                options.CallbackPath = oidcOptions.CallbackPath;
                options.SignedOutCallbackPath = oidcOptions.SignedOutCallbackPath;
                options.RemoteSignOutPath = oidcOptions.RemoteSignOutPath;
                options.SignedOutRedirectUri = oidcOptions.SignedOutRedirectPath;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.SaveTokens = true;
                options.UsePkce = true;
                options.GetClaimsFromUserInfoEndpoint = oidcOptions.GetClaimsFromUserInfoEndpoint;
                options.RequireHttpsMetadata = oidcOptions.RequireHttpsMetadata;

                options.Scope.Clear();
                foreach (var scope in scopeResolver.EffectiveLoginScopes)
                {
                    options.Scope.Add(scope);
                }

                options.Events = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProvider = context =>
                    {
                        context.ProtocolMessage ??= new OpenIdConnectMessage();

                        if (context.Properties.Items.TryGetValue(AuthenticationEndpoints.DomainHintParameterName, out var domainHint) &&
                            !string.IsNullOrWhiteSpace(domainHint))
                        {
                            context.ProtocolMessage.SetParameter(AuthenticationEndpoints.DomainHintParameterName, domainHint);
                        }

                        return Task.CompletedTask;
                    },
                    OnAuthorizationCodeReceived = async context =>
                    {
                        var providerOptions = context.HttpContext.RequestServices
                            .GetRequiredService<IOptions<OidcProviderOptions>>()
                            .Value;
                        if (providerOptions.ClientAuthenticationMethod != OidcClientAuthenticationMethod.PrivateKeyJwt)
                        {
                            return;
                        }

                        var assertionService = context.HttpContext.RequestServices.GetRequiredService<IOidcClientAssertionService>();
                        context.TokenEndpointRequest ??= new OpenIdConnectMessage();
                        context.TokenEndpointRequest.ClientSecret = null;
                        context.TokenEndpointRequest.Parameters.Remove(OpenIdConnectParameterNames.ClientSecret);
                        context.TokenEndpointRequest.ClientAssertionType = OidcAuthenticationConstants.ClientAssertions.JwtBearerType;
                        var tokenEndpoint = await ResolveTokenEndpointForAuthorizationCodeRedemptionAsync(
                            context,
                            context.HttpContext.RequestAborted);
                        context.TokenEndpointRequest.ClientAssertion = assertionService.CreateClientAssertion(tokenEndpoint);
                    },
                    OnRemoteFailure = context =>
                    {
                        var classification = OidcRemoteFailureClassifier.Classify(context);
                        if (!classification.IsHandledRemoteFailure || !classification.ShouldRedirect)
                        {
                            return Task.CompletedTask;
                        }

                        var logger = context.HttpContext.RequestServices
                            .GetRequiredService<ILoggerFactory>()
                            .CreateLogger("Recrovit.AspNetCore.Authentication.OpenIdConnect.RemoteFailure");
                        var hostOptions = context.HttpContext.RequestServices
                            .GetRequiredService<IOptions<OidcAuthenticationOptions>>()
                            .Value;
                        var traceIdentifier = context.HttpContext.TraceIdentifier;
                        using var scope = logger.BeginScope(OidcLogScopes.Create(
                            traceIdentifier,
                            providerName: activeProviderName,
                            endpoint: options.CallbackPath));

                        OidcInfrastructureLog.RemoteFailureIntercepted(
                            logger,
                            activeProviderName,
                            classification.Kind.ToString(),
                            classification.Error ?? "(none)",
                            classification.ShouldRedirect,
                            classification.ShouldCleanupCorrelationCookies);

                        if (classification.ShouldCleanupCorrelationCookies)
                        {
                            OidcRemoteFailureClassifier.DeleteTransientCookies(context.HttpContext, options);
                        }

                        context.HandleResponse();
                        context.Response.Redirect(OidcRemoteFailureClassifier.GetSafeRedirectPath(hostOptions.RemoteFailureRedirectPath));
                        OidcInfrastructureLog.RemoteFailureRedirected(
                            logger,
                            activeProviderName,
                            classification.Kind.ToString(),
                            classification.ShouldCleanupCorrelationCookies);
                        return Task.CompletedTask;
                    },
                    OnTicketReceived = async context =>
                    {
                        var tokenStore = context.HttpContext.RequestServices.GetRequiredService<IDownstreamUserTokenStore>();
                        var ticketLogger = context.HttpContext.RequestServices
                            .GetRequiredService<ILoggerFactory>()
                            .CreateLogger("Recrovit.AspNetCore.Authentication.OpenIdConnect.Ticket");
                        using var scope = ticketLogger.BeginScope(OidcLogScopes.Create(
                            context.HttpContext.TraceIdentifier,
                            providerName: activeProviderName,
                            endpoint: options.CallbackPath,
                            flowStep: "ticket-received"));
                        OidcInfrastructureLog.TicketReceived(ticketLogger, activeProviderName);
                        var authenticationProperties = context.Properties
                            ?? throw new InvalidOperationException("The OIDC ticket did not include authentication properties.");
                        var principal = context.Principal
                            ?? throw new InvalidOperationException("The authenticated principal is not available.");
                        var hostOptions = context.HttpContext.RequestServices
                            .GetRequiredService<IOptions<OidcAuthenticationOptions>>()
                            .Value;
                        var timeProvider = context.HttpContext.RequestServices.GetRequiredService<TimeProvider>();
                        EnsureLocalSessionIdClaim(principal);
                        OidcSessionTimeoutMetadata.StampSessionLifetime(principal, hostOptions, timeProvider);
                        await tokenStore.StoreSessionTokenSetAsync(
                            principal,
                            StoredOidcSessionTokenSet.FromAuthenticationProperties(authenticationProperties),
                            context.HttpContext.RequestAborted);
                        OidcInfrastructureLog.SessionTokenPersisted(ticketLogger, activeProviderName);

                        // Persist the tokens outside the authentication cookie.
                        authenticationProperties.StoreTokens([]);
                        OidcInfrastructureLog.TicketTokensCleared(ticketLogger, activeProviderName);
                    }
                };
            });

        services.AddAuthorization();
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, ApiAwareAuthorizationMiddlewareResultHandler>();

        var hostSecurityOptions = infrastructureSection.Get<HostSecurityOptions>();
        var dataProtectionBuilder = services.AddDataProtection();
        if (!string.IsNullOrWhiteSpace(hostSecurityOptions?.DataProtectionKeysPath))
        {
            dataProtectionBuilder.PersistKeysToFileSystem(new DirectoryInfo(hostSecurityOptions.DataProtectionKeysPath));
        }

        services.AddSingleton<IStartupFilter>(_ => new ConfigurationStartupFilter(environment));

        return services;
    }

    private static async Task<string> ResolveTokenEndpointForAuthorizationCodeRedemptionAsync(
        AuthorizationCodeReceivedContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var tokenEndpoint = context.TokenEndpointRequest?.IssuerAddress;
        if (!string.IsNullOrWhiteSpace(tokenEndpoint))
        {
            return tokenEndpoint;
        }

        tokenEndpoint = context.Options.Configuration?.TokenEndpoint;
        if (!string.IsNullOrWhiteSpace(tokenEndpoint))
        {
            return tokenEndpoint;
        }

        if (context.Options.ConfigurationManager is not null)
        {
            var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(cancellationToken);
            if (!string.IsNullOrWhiteSpace(configuration.TokenEndpoint))
            {
                return configuration.TokenEndpoint;
            }
        }

        throw new InvalidOperationException(
            "The token endpoint is not available from the authorization code redemption request, the static OIDC configuration, or the OIDC metadata.");
    }

    private static bool IsValidPath(string? path)
    {
        return !string.IsNullOrWhiteSpace(path) &&
            path.StartsWith("/", StringComparison.Ordinal) &&
            !path.StartsWith("//", StringComparison.Ordinal);
    }

    private static void EnsureLocalSessionIdClaim(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.HasClaim(static claim => claim.Type == OidcAuthenticationConstants.ProviderClaimNames.LocalSessionId))
        {
            return;
        }

        var identity = principal.Identities.FirstOrDefault(static candidate => candidate.IsAuthenticated);
        if (identity is null)
        {
            throw new InvalidOperationException("The authenticated principal does not contain a writable identity.");
        }

        identity.AddClaim(new Claim(
            OidcAuthenticationConstants.ProviderClaimNames.LocalSessionId,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(32))));
    }

    private sealed class ConfigurationStartupFilter(IWebHostEnvironment environment) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                ValidateProductionReadiness(app.ApplicationServices, environment);
                next(app);
            };
        }

        private static void ValidateProductionReadiness(IServiceProvider services, IWebHostEnvironment environment)
        {
            var providerOptions = services.GetRequiredService<IOptions<ActiveOidcProviderOptions>>().Value;
            var logger = services.GetRequiredService<ILoggerFactory>()
                .CreateLogger("Recrovit.AspNetCore.Authentication.OpenIdConnect.Startup");
            var scopeResolver = services.GetRequiredService<OidcScopeResolver>();
            var downstreamApiCatalog = services.GetRequiredService<DownstreamApiCatalog>();
            var hostOptions = services.GetRequiredService<IOptions<OidcAuthenticationOptions>>().Value;
            var hostSecurityOptions = services.GetRequiredService<IOptions<HostSecurityOptions>>().Value;
            OidcInfrastructureLog.InfrastructureInitialized(
                logger,
                providerOptions.ProviderName,
                string.Join(", ", downstreamApiCatalog.Apis.Keys.OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)),
                hostOptions.SessionValidationDownstreamApiName ?? "<none>",
                hostSecurityOptions.ForwardedHeadersEnabled,
                !string.IsNullOrWhiteSpace(hostSecurityOptions.DataProtectionKeysPath));

            if (scopeResolver.EffectiveLoginScopes.Length == 0)
            {
                OidcInfrastructureLog.StartupValidationFailed(
                    logger,
                    "effective-scopes",
                    "No non-empty effective OIDC scopes were configured.");
                throw new InvalidOperationException(
                    $"{OpenIdConnectConfigurationResolver.RootSectionName}:Providers:<provider>:Scopes and downstream API scopes must define at least one non-empty effective scope.");
            }

            if (!environment.IsProduction())
            {
                return;
            }

            var oidcOptions = services.GetRequiredService<IOptions<OidcProviderOptions>>().Value;

            var authorityHttpsError = OidcEndpointHttpsValidator.GetProductionRequirementError(
                oidcOptions.Authority,
                environment,
                $"{OpenIdConnectConfigurationResolver.RootSectionName}:Providers:<provider>:Authority");
            if (authorityHttpsError is not null)
            {
                OidcInfrastructureLog.StartupValidationFailed(logger, "authority-https", authorityHttpsError);
                throw new InvalidOperationException(authorityHttpsError);
            }

            var forwardedHeadersError = ForwardedHeadersConfiguration.GetProductionRequirementError(hostSecurityOptions, environment);
            if (forwardedHeadersError is not null)
            {
                OidcInfrastructureLog.StartupValidationFailed(logger, "forwarded-headers", forwardedHeadersError);
                throw new InvalidOperationException(forwardedHeadersError);
            }

            var distributedCache = services.GetRequiredService<IDistributedCache>();
            if (distributedCache is MemoryDistributedCache)
            {
                OidcInfrastructureLog.StartupValidationFailed(
                    logger,
                    "distributed-cache",
                    "Production requires a shared distributed cache for user token storage.");
                throw new InvalidOperationException(
                    "Production requires a shared distributed cache for user token storage. Replace AddDistributedMemoryCache with a shared implementation.");
            }

            if (string.IsNullOrWhiteSpace(hostSecurityOptions.DataProtectionKeysPath))
            {
                OidcInfrastructureLog.StartupValidationFailed(
                    logger,
                    "data-protection-keys",
                    $"Production requires {OpenIdConnectConfigurationResolver.RootSectionName}:Infrastructure:DataProtectionKeysPath for shared Data Protection keys.");
                throw new InvalidOperationException(
                    $"Production requires {OpenIdConnectConfigurationResolver.RootSectionName}:Infrastructure:DataProtectionKeysPath for shared Data Protection keys.");
            }
        }
    }
}
