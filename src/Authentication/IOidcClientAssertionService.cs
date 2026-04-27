namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

internal interface IOidcClientAssertionService
{
    string CreateClientAssertion(string tokenEndpoint);
}
