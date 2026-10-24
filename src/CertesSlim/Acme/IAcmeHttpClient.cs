namespace CertesSlim.Acme;

/// <summary>
/// Supports HTTP operations for ACME servers.
/// </summary>
public interface IAcmeHttpClient
{
    /// <summary>
    /// Gets the nonce for next request.
    /// </summary>
    /// <returns>
    /// The nonce.
    /// </returns>
    Task<string> ConsumeNonce();

    /// <summary>
    /// Posts the data to the specified URI.
    /// </summary>
    /// <typeparam name="T">The type of expected result</typeparam>
    /// <typeparam name="TPayload">The type of sent payload</typeparam>
    /// <param name="uri">The URI.</param>
    /// <param name="payload">The payload.</param>
    /// <returns>The response from ACME server.</returns>
    Task<AcmeHttpResponse<T>> Post<T, TPayload>(Uri uri, TPayload payload);

    /// <summary>
    /// Gets the data from specified URI.
    /// </summary>
    /// <typeparam name="T">The type of expected result</typeparam>
    /// <param name="uri">The URI.</param>
    /// <returns>The response from ACME server.</returns>
    Task<AcmeHttpResponse<T>> Get<T>(Uri uri);
}