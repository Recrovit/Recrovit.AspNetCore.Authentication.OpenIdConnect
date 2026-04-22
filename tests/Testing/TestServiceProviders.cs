using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Tests.Testing;

internal static class TestServiceProviders
{
    public static IServiceProvider CreateServiceProviderForSignOut()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
        return services.BuildServiceProvider();
    }
}
