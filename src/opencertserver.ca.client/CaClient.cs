using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Protocol;
using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Ca.Client;

/// <summary>
/// HTTP client for a backing certificate authority. It is the outbound half of the "trusted connection"
/// to a CA and is used by both a remote ACME issuer and an RA delegator. All operations go over HTTPS
/// using mTLS or a bearer token; the CA remains authoritative for scope and identity, so this client
/// never makes a local scope decision.
/// </summary>
public sealed partial class CaClient
{
    private readonly HttpClient _httpClient;
    private readonly CaClientOptions _options;
    private readonly ILogger<CaClient> _logger;

    /// <summary>
    /// Meter for the trusted remote link. Exporters read it when OpenTelemetry is enabled; it is inert
    /// otherwise. Counters use a <c>result</c> tag so operators can distinguish successful calls from
    /// CA rejections (out-of-scope) and revocation outcomes.
    /// </summary>
    public static readonly Meter Meter = new("opencertserver.ca.client");

    private static readonly Counter<int> SignCounter =
        Meter.CreateCounter<int>("opencertserver.ca.client.sign", "operations", "result");

    private static readonly Counter<int> RevokeCounter =
        Meter.CreateCounter<int>("opencertserver.ca.client.revoke", "operations", "result");

    /// <summary>Creates a backing-CA client over the supplied HTTPS <see cref="HttpClient"/>.</summary>
    public CaClient(HttpClient httpClient, CaClientOptions options, ILogger<CaClient> logger)
    {
        _httpClient = httpClient;
        _options = options;
        _logger = logger;
        if (_options.BaseUrl.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Backings CA connections must use HTTPS.", nameof(options));
        }
    }

    /// <summary>The backing CA base address used by this client.</summary>
    public Uri BaseUrl => _options.BaseUrl;

    /// <summary>The default certificate profile configured for the backing CA client.</summary>
    public string? Profile => _options.Profile;

    /// <summary>
    /// Submits a PKCS#10 request to the backing CA and returns the signed result, or a typed error
    /// when the CA rejects it. Out-of-scope requests surface as <see cref="SignCertificateResponse.Error"/>
    /// so a remote issuer can map them to an ACME order failure.
    /// </summary>
    public async Task<SignCertificateResponse> SignCsr(
        string csrPem,
        string? profile = null,
        string? delegatedScope = null,
        X509Certificate2? reenrollingFrom = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(csrPem);
        var effectiveProfile = profile ?? _options.Profile;
        var effectiveScope = delegatedScope ?? _options.DelegatedScope;

        var path = RaProtocol.CsrPathFor(effectiveProfile);
        if (notBefore.HasValue || notAfter.HasValue)
        {
            var query = new List<string>();
            if (notBefore.HasValue)
            {
                query.Add($"notBefore={Uri.EscapeDataString(notBefore.Value.UtcDateTime.ToString("o"))}");
            }

            if (notAfter.HasValue)
            {
                query.Add($"notAfter={Uri.EscapeDataString(notAfter.Value.UtcDateTime.ToString("o"))}");
            }

            path += "?" + string.Join("&", query);
        }

        var requestUri = new Uri(_options.BaseUrl, path);
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUri);
        request.Content = new StringContent(csrPem, Encoding.UTF8, RaProtocol.CsrMimeType);
        // A remote SCEP/EST peer that cannot host the CA core carries the previous certificate over the
        // wire so the CA can supersede-revoke it on the new one; absence leaves first-enrollment unchanged.
        if (reenrollingFrom is not null)
        {
            request.Headers.TryAddWithoutValidation(RaProtocol.ReenrollingFromHeader,
                reenrollingFrom.ExportCertificatePem());
        }

        ApplyAuth(request, effectiveScope);

        LogSigningCsrViaBackingCaAtUri(requestUri);
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            SignCounter.Add(1, new KeyValuePair<string, object?>("result", "success"));
            return ParseChain(body);
        }

        LogBackingsCaRejectedTheCsrWithHttpStatusDetail((int)response.StatusCode, body);
        SignCounter.Add(1, new KeyValuePair<string, object?>("result", "rejected"));
        return new SignCertificateResponse.Error(false, SplitErrors(body));
    }

    /// <summary>
    /// Requests revocation of a certificate, signing the proof-of-possession message with the supplied
    /// identity. A <c>404</c> means the certificate was not found and is reported as <c>false</c>; any
    /// other non-success status is surfaced as an exception.
    /// </summary>
    public async Task<bool> Revoke(
        X509Certificate2 identity,
        string serialNumberHex,
        string? profile,
        X509RevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentException.ThrowIfNullOrWhiteSpace(serialNumberHex);
        if (!identity.HasPrivateKey)
        {
            throw new ArgumentException("The revoking identity must have its private key.", nameof(identity));
        }

        var reasonName = reason.ToString();
        var signature = Sign(identity, RaProtocol.BuildRevocationMessage(serialNumberHex, reasonName));
        var profileName = profile ?? _options.Profile;
        var requestUri = new Uri(_options.BaseUrl,
            $"{RaProtocol.RevokePath}?{(string.IsNullOrEmpty(profileName)
                ? ""
                : $"{RaProtocol.QueryProfile}={Uri.EscapeDataString(profileName)}&")}&{RaProtocol.QuerySn}={Uri.EscapeDataString(serialNumberHex)}&{RaProtocol.QueryReason}={Uri.EscapeDataString(reasonName)}&{RaProtocol.QuerySignature}={Uri.EscapeDataString(Convert.ToBase64String(signature))}");
        using var request = new HttpRequestMessage(HttpMethod.Delete, requestUri);
        ApplyAuth(request);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            RevokeCounter.Add(1, new KeyValuePair<string, object?>("result", "not_found"));
            return false;
        }

        try
        {
            response.EnsureSuccessStatusCode();
        }
        catch
        {
            RevokeCounter.Add(1, new KeyValuePair<string, object?>("result", "error"));
            throw;
        }

        RevokeCounter.Add(1, new KeyValuePair<string, object?>("result", "revoked"));
        return true;
    }

    /// <summary>Fetches the root/trust-anchor certificates published by the backing CA.</summary>
    public async Task<X509Certificate2Collection> GetRootCertificates(
        string? profile = null,
        CancellationToken cancellationToken = default)
    {
        var path = profile == null
            ? _options.RootsPath
            : $"{_options.RootsPath}/{profile}";
        var requestUri = new Uri(_options.BaseUrl, path);
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        ApplyAuth(request);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var pem = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(pem);
        return collection;
    }

    /// <summary>
    /// Fetches the full published chain (issuing CA plus the root, and any published intermediates)
    /// the backing CA serves for the given profile. A SCEP or EST peer that cannot host the CA core
    /// uses this for its GetCACert chain and renewal anchors, so the CA stays authoritative for what
    /// is published.
    /// </summary>
    public async Task<X509Certificate2Collection> GetPublishedCertificates(
        string? profile = null,
        CancellationToken cancellationToken = default)
    {
        var path = RaProtocol.PublishedPathFor(profile);
        var requestUri = new Uri(_options.BaseUrl, path);
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        ApplyAuth(request);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var pem = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(pem);
        return collection;
    }

    ///<summary>
    /// refresh call: an RA may call it at startup to learn the profiles to offer and again later to
    /// pick up a profile set the CA has updated. Only names come back over the wire.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetProfiles(CancellationToken cancellationToken = default)
    {
        var requestUri = new Uri(_options.BaseUrl, RaProtocol.ProfilesPath);
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        ApplyAuth(request);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return [.. body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
    }

    /// <summary>Fetches the revocation list (DER CRL) published by the backing CA.</summary>
    public async Task<byte[]> GetRevocationList(
        string? profile = null,
        CancellationToken cancellationToken = default)
    {
        var path = profile == null
            ? _options.RevocationListPath
            : string.Format(System.Globalization.CultureInfo.InvariantCulture, RaProtocol.ProfileCrlPathFormat,
                Uri.EscapeDataString(profile));
        var requestUri = new Uri(_options.BaseUrl, path);
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        ApplyAuth(request);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
    }

    private void ApplyAuth(HttpRequestMessage request, string? delegatedScope = null)
    {
        var scope = delegatedScope ?? _options.DelegatedScope;
        if (!string.IsNullOrWhiteSpace(scope))
        {
            request.Headers.Add(RaProtocol.DelegatedSubjectHeader, scope);
        }

        if (!string.IsNullOrWhiteSpace(_options.BearerToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _options.BearerToken);
        }
    }

    private static SignCertificateResponse ParseChain(string pem)
    {
        var chain = new X509Certificate2Collection();
        chain.ImportFromPem(pem);
        if (chain.Count == 0)
        {
            throw new InvalidDataException("The backing CA returned an empty certificate chain.");
        }

        var leaf = chain[0];
        var issuers = new X509Certificate2Collection();
        for (var i = 1; i < chain.Count; i++)
        {
            issuers.Add(chain[i]);
        }

        return new SignCertificateResponse.Success(leaf, issuers);
    }

    private static string[] SplitErrors(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return ["The backing CA rejected the request."];
        }

        return body.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static byte[] Sign(X509Certificate2 certificate, string value)
    {
        var data = Encoding.UTF8.GetBytes(value);
        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa != null)
        {
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        using var ecdsa = certificate.GetECDsaPrivateKey();
        return ecdsa?.SignData(data, HashAlgorithmName.SHA256)
         ?? throw new NotSupportedException("The revoking identity must use RSA or ECDSA.");
    }

    [LoggerMessage(LogLevel.Debug, "Signing CSR via backing CA at {Uri}")]
    partial void LogSigningCsrViaBackingCaAtUri(Uri uri);

    [LoggerMessage(LogLevel.Warning, "Backings CA rejected the CSR with HTTP {Status}: {Detail}")]
    partial void LogBackingsCaRejectedTheCsrWithHttpStatusDetail(int status, string detail);
}
