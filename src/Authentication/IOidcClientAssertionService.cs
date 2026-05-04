namespace Recrovit.AspNetCore.Authentication.OpenIdConnect.Authentication;

/// <summary>
/// Creates client assertions for token endpoint authentication flows such as <c>private_key_jwt</c>.
/// </summary>
public interface IOidcClientAssertionService
{
    /// <summary>
    /// Creates a client assertion for the specified token endpoint.
    /// </summary>
    /// <param name="tokenEndpoint">The absolute token endpoint URI.</param>
    /// <returns>A signed client assertion.</returns>
    string CreateClientAssertion(string tokenEndpoint);
}
