using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Protocol;

namespace OpenCertServer.Ra;

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
    /// <param name="csrPem">The PKCS#10 certificate request.</param>
    /// <param name="profile">
    /// The CA profile to enroll against, or null to use the peer's default profile
    /// (<see cref="RaPeerOptions.Profile"/>). This lets one RA serve multiple CA profiles.
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    public Task<string> EnrollAsync(
        string csrPem,
        string? profile = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(csrPem);
        var effectiveProfile = profile ?? _options.Profile;
        var path = RaProtocol.CsrPathFor(effectiveProfile);
        return SendForCertificateAsync(new Uri(_options.PeerUrl, path), csrPem, cancellationToken);
    }

    /// <summary>
    /// Requests the set of profiles the backing CA supports, so the RA can discover and offer the full
    /// set and refresh it later to pick up a profile set the CA has updated. Only profile names come
    /// back over the wire.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetSupportedProfiles(CancellationToken cancellationToken = default)
    {
        var requestUri = new Uri(_options.PeerUrl, RaProtocol.ProfilesPath);
        using var request = CreateRequest(HttpMethod.Get, requestUri);
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }

    /// <summary>
    /// Renews a certificate by submitting its replacement PKCS#10 request. Domain validation and
    /// enrollment policy remain the responsibility of the central CA's configured protocol.
    /// </summary>
    public Task<string> RenewAsync(string csrPem, CancellationToken cancellationToken = default)
    {
        return EnrollAsync(csrPem, _options.Profile, cancellationToken);
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
        var signature = Sign(raIdentityCertificate, RaProtocol.BuildRevocationMessage(serialNumberHex, reasonName));
        var profileName = _options.Profile;
        var profileQuery = string.IsNullOrWhiteSpace(profileName)
            ? string.Empty
            : $"{RaProtocol.QueryProfile}={Uri.EscapeDataString(profileName)}&";
        var requestUri = new Uri(_options.PeerUrl,
            $"{RaProtocol.RevokePath}?{profileQuery}{RaProtocol.QuerySn}={Uri.EscapeDataString(serialNumberHex)}" +
            $"&{RaProtocol.QueryReason}={Uri.EscapeDataString(reasonName)}" +
            $"&{RaProtocol.QuerySignature}={Uri.EscapeDataString(Convert.ToBase64String(signature))}");
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
        request.Headers.Add(RaProtocol.DelegatedSubjectHeader, _options.Scope);
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
