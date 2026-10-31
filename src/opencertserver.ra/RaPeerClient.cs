namespace OpenCertServer.Ra;

using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Outbound-only client for a registration authority that delegates enrollment to a central CA.
/// The RA does not host or expose an inbound CA endpoint.
/// </summary>
public sealed class RaPeerClient
{
    private readonly HttpClient _httpClient;
    private readonly RaPeerOptions _options;

    /// <summary>Creates a peer client using the supplied outbound HTTP client.</summary>
    public RaPeerClient(HttpClient httpClient, RaPeerOptions options)
    {
        _httpClient = httpClient;
        _options = options;
        if (_options.PeerUrl.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("RA peer connections must use HTTPS.", nameof(options));
        }
    }

    /// <summary>The central CA URL used by this peer client.</summary>
    public Uri PeerUrl => _options.PeerUrl;

    /// <summary>Submits a proof-of-possession PKCS#10 request to the central CA.</summary>
    public Task<string> EnrollAsync(string csrPem, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(csrPem);
        var path = string.IsNullOrWhiteSpace(_options.Profile)
            ? "ca/csr"
            : $"ca/{Uri.EscapeDataString(_options.Profile)}/csr";
        return SendForCertificateAsync(new Uri(_options.PeerUrl, path), csrPem, cancellationToken);
    }

    /// <summary>
    /// Renews a certificate by submitting its replacement PKCS#10 request. Domain validation and
    /// enrollment policy remain the responsibility of the central CA's configured protocol.
    /// </summary>
    public Task<string> RenewAsync(string csrPem, CancellationToken cancellationToken = default)
    {
        return EnrollAsync(csrPem, cancellationToken);
    }

    /// <summary>Requests revocation of a certificate in the delegated DNS scope.</summary>
    public async Task<bool> RevokeAsync(
        X509Certificate2 raIdentityCertificate,
        string serialNumberHex,
        X509RevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(raIdentityCertificate);
        ArgumentException.ThrowIfNullOrWhiteSpace(serialNumberHex);
        if (!raIdentityCertificate.HasPrivateKey)
        {
            throw new ArgumentException("The RA identity certificate must have its private key.", nameof(raIdentityCertificate));
        }

        var reasonName = reason.ToString();
        var signature = Sign(raIdentityCertificate, serialNumberHex + reasonName);
        var requestUri = new Uri(_options.PeerUrl,
            $"ca/revoke?sn={Uri.EscapeDataString(serialNumberHex)}" +
            $"&reason={Uri.EscapeDataString(reasonName)}" +
            $"&signature={Uri.EscapeDataString(Convert.ToBase64String(signature))}");
        using var request = CreateRequest(HttpMethod.Delete, requestUri);
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return false;
        }

        response.EnsureSuccessStatusCode();
        return response.IsSuccessStatusCode;
    }

    private async Task<string> SendForCertificateAsync(
        Uri requestUri,
        string csrPem,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(HttpMethod.Post, requestUri);
        request.Content = new StringContent(csrPem, System.Text.Encoding.UTF8, "application/pkcs10");
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }

    private HttpRequestMessage CreateRequest(HttpMethod method, Uri requestUri)
    {
        if (requestUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("RA peer requests must use HTTPS.");
        }

        var request = new HttpRequestMessage(method, requestUri);
        request.Headers.Add("X-Delegated-Subject", _options.Scope);
        if (!string.IsNullOrWhiteSpace(_options.BearerToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.BearerToken);
        }

        return request;
    }

    private static byte[] Sign(X509Certificate2 certificate, string value)
    {
        var data = System.Text.Encoding.UTF8.GetBytes(value);
        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa != null)
        {
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        using var ecdsa = certificate.GetECDsaPrivateKey();
        return ecdsa?.SignData(data, HashAlgorithmName.SHA256)
               ?? throw new NotSupportedException("The RA identity certificate must use RSA or ECDSA.");
    }
}

/// <summary>Dependency-injection extensions for the outbound RA peer.</summary>
public static class RaPeerServiceCollectionExtensions
{
    /// <summary>Registers a configured HTTPS-only peer client.</summary>
    public static IServiceCollection AddRaPeerClient(
        this IServiceCollection services,
        Microsoft.Extensions.Configuration.IConfiguration configuration)
    {
        return services.AddRaPeerClient(configuration, null);
    }

    /// <summary>
    /// Registers a configured HTTPS-only peer client and optionally configures its outbound TLS
    /// handler, for example to present an RA client certificate.
    /// </summary>
    public static IServiceCollection AddRaPeerClient(
        this IServiceCollection services,
        Microsoft.Extensions.Configuration.IConfiguration configuration,
        Action<HttpClientHandler>? configureHandler)
    {
        var options = RaPeerOptions.FromConfiguration(configuration);
        services.AddSingleton(options);
        services.AddHttpClient<RaPeerClient>()
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                var handler = new HttpClientHandler();
                configureHandler?.Invoke(handler);
                return handler;
            });
        return services;
    }
}
