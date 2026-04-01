namespace OpenCertServer.Est.Client;

using System;
using System.Formats.Asn1;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ca.Utils;
using OpenCertServer.Ca.Utils.Pkcs7;
using OpenCertServer.Ca.Utils.X509.Templates;

/// <summary>
/// Defines an EST client for enrolling and re-enrolling certificates.
/// </summary>
public sealed class EstClient : IDisposable
{
    private readonly Uri _estHost;
    private readonly string? _profileName;
    private readonly HttpMessageHandler _messageHandler;
    private readonly HttpClient _messageClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="EstClient"/> class.
    /// </summary>
    /// <param name="estHost">The <see cref="Uri"/> of the EST server.</param>
    /// <param name="profileName">The optional profile name to use for the EST server.</param>
    /// <param name="messageHandler">The optional <see cref="HttpMessageHandler"/> for handling server requests.</param>
    /// <exception cref="ArgumentException">Thrown if the <see cref="Uri"/> scheme of the server is not HTTPS.</exception>
    public EstClient(Uri estHost, string? profileName = null, HttpMessageHandler? messageHandler = null)
    {
        if (estHost.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Must use HTTPS", nameof(estHost));
        }

        _estHost = estHost;
        _profileName = profileName;
        _messageHandler = messageHandler ?? new SocketsHttpHandler();
        _messageClient = new HttpClient(_messageHandler);
    }

    /// <summary>
    /// Requests a new certificate from the EST server.
    /// </summary>
    /// <param name="distinguishedName">The <see cref="X500DistinguishedName"/> of the requestor.</param>
    /// <param name="key">The <see cref="AsymmetricAlgorithm"/> to enroll.</param>
    /// <param name="usageFlags">The certificate <see cref="X509KeyUsageFlags"/>.</param>
    /// <param name="authenticationHeader">The authentication value to pass to the server.</param>
    /// <param name="certificate">The <see cref="X509Certificate2"/> to use if enrolling or authenticating with certificate.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> to use for the async operation.</param>
    /// <typeparam name="TAlgorithm">The <see cref="Type"/> of asymmetric key algorithm. The algorithm must be either <see cref="RSA"/> or <see cref="ECDsa"/>.</typeparam>
    /// <returns></returns>
    public Task<(string?, X509Certificate2Collection?)> Enroll<TAlgorithm>(
        X500DistinguishedName distinguishedName,
        TAlgorithm key,
        X509KeyUsageFlags usageFlags,
        AuthenticationHeaderValue? authenticationHeader = null,
        X509Certificate2? certificate = null,
        CancellationToken cancellationToken = default) where TAlgorithm : AsymmetricAlgorithm
    {
        var request = CreateCertificateRequest(distinguishedName, key, usageFlags);
        return RequestEnrollCerts(_profileName, request, authenticationHeader, certificate, cancellationToken);
    }

    /// <summary>
    /// Re-enrolls, i.e., renews, a certificate from the EST server.
    /// </summary>
    /// <param name="key">The <see cref="AsymmetricAlgorithm"/> key to sign the request.</param>
    /// <param name="certificate">The <see cref="X509Certificate2"/> to re-enroll.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> to use for the async operation.</param>
    /// <typeparam name="TAlgorithm">The <see cref="Type"/> of asymmetric key algorithm. The algorithm must be either <see cref="RSA"/> or <see cref="ECDsa"/>.</typeparam>
    /// <returns>An updated <see cref="X509Certificate2Collection"/> with the renewed certificate and issuer chain.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the re-enroll request to the server fails.</exception>
    public Task<(string?, X509Certificate2Collection?)> ReEnroll<TAlgorithm>(
        TAlgorithm key,
        X509Certificate2 certificate,
        CancellationToken cancellationToken = default) where TAlgorithm : AsymmetricAlgorithm
    {
        var certRequest = CreateCertificateRequest(
            certificate.SubjectName,
            key,
            certificate.Extensions.OfType<X509KeyUsageExtension>()
                .Aggregate(X509KeyUsageFlags.None, (flags, ext) => flags | ext.KeyUsages));

        return RequestReEnrollCerts(certificate, certRequest, cancellationToken);
    }

    public async Task<X509Certificate2Collection> ServerCertificates(CancellationToken cancellationToken = default)
    {
        var pathValue = _profileName == null ? "/.well-known/est/cacerts" : $"/.well-known/est/{_profileName}/cacerts";
        var requestUriBuilder = new UriBuilder(
            Uri.UriSchemeHttps,
            _estHost.Host,
            _estHost.Port,
            pathValue);

        var response = await _messageClient
            .GetAsync(requestUriBuilder.Uri, HttpCompletionOption.ResponseContentRead, cancellationToken)
            .ConfigureAwait(false);
        var b64 = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var bytes = Convert.FromBase64String(b64);
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        var contentInfo = new CmsContentInfo(reader);
        if(contentInfo.ContentType.Value != Oids.Pkcs7Signed)
        {
            throw new InvalidOperationException("Expected signed data from server");
        }
        reader = new AsnReader(contentInfo.EncodedContent, AsnEncodingRules.DER);
        var signedData = new SignedData(reader);
        return new X509Certificate2Collection(signedData.Certificates ?? []);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _messageClient.CancelPendingRequests();
        _messageHandler.Dispose();
        _messageClient.Dispose();
    }

    public async Task<CertificateSigningRequestTemplate> GetCsrAttributes(
        AuthenticationHeaderValue? authenticationHeader)
    {
        var pathValue = _profileName == null
            ? "/.well-known/est/csrattrs"
            : $"/.well-known/est/{_profileName}/csrattrs";
        var requestUriBuilder = new UriBuilder(
            Uri.UriSchemeHttps,
            _estHost.Host,
            _estHost.Port,
            pathValue);

        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Get,
            RequestUri = requestUriBuilder.Uri
        };
        request.Headers.Authorization = authenticationHeader;
        var response = await _messageClient
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
            .ConfigureAwait(false);
        response = response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        return new CertificateSigningRequestTemplate(new AsnReader(bytes, AsnEncodingRules.DER,
            new AsnReaderOptions { SkipSetSortOrderVerification = true }));
    }

    private async Task<(string?, X509Certificate2Collection?)> RequestReEnrollCerts(
        X509Certificate2 certificate,
        CertificateRequest certRequest,
        CancellationToken cancellationToken)
    {
        var content = new StringContent(certRequest.ToPkcs10(), Encoding.UTF8, "application/pkcs10-mime");
        var pathValue = _profileName == null
            ? "/.well-known/est/simplereenroll"
            : $"/.well-known/est/{_profileName}/simplereenroll";
        var requestUriBuilder = new UriBuilder(
            Uri.UriSchemeHttps,
            _estHost.Host,
            _estHost.Port,
            pathValue);
        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = requestUriBuilder.Uri,
            Content = content
        };

        request.Headers.Add("X-Client-Cert", Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));
        if (_messageHandler is HttpClientHandler clientHandler)
        {
            clientHandler.ClientCertificates.Clear();
            clientHandler.ClientCertificates.Add(certificate);
        }

        var response = await _messageClient
            .SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken)
            .ConfigureAwait(false);
        if (_messageHandler is HttpClientHandler ch)
        {
            ch.ClientCertificates.Clear();
        }

        if (response is { IsSuccessStatusCode: false, Content.Headers.ContentType: not null })
        {
            if (response.Content.Headers.ContentType.MediaType?.Equals("text/plain",
                StringComparison.OrdinalIgnoreCase) == true)
            {
                return (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false), null);
            }

            return ("Error retrieving certificate", null);
        }

        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var reader = new AsnReader(bytes, AsnEncodingRules.DER,
            new AsnReaderOptions { SkipSetSortOrderVerification = true });
        var contentInfo = new CmsContentInfo(reader);
        if(contentInfo.ContentType.Value != Oids.Pkcs7Signed)
        {
            throw new InvalidOperationException("Expected signed data from server");
        }
        reader = new AsnReader(contentInfo.EncodedContent, AsnEncodingRules.DER);
        var signedData = new SignedData(reader);
        return (null, new X509Certificate2Collection(signedData.Certificates ?? []));
    }

    private async Task<(string?, X509Certificate2Collection?)> RequestEnrollCerts(
        string? profileName,
        CertificateRequest request,
        AuthenticationHeaderValue? authenticationHeader = null,
        X509Certificate2? certificate = null,
        CancellationToken cancellationToken = default)
    {
        var pathValue = profileName == null
            ? "/.well-known/est/simpleenroll"
            : $"/.well-known/est/{profileName}/simpleenroll";
        var requestUriBuilder = new UriBuilder(
            Uri.UriSchemeHttps,
            _estHost.Host,
            _estHost.Port,
            pathValue);
        var requestMessage = new HttpRequestMessage
        {
            Content = new StringContent(request.ToPkcs10(), Encoding.UTF8, "application/pkcs10"),
            Method = HttpMethod.Post,
            RequestUri = requestUriBuilder.Uri,
            Headers =
            {
                TransferEncoding = { new TransferCodingHeaderValue("base64") }
            }
        };
        if (authenticationHeader != null)
        {
            requestMessage.Headers.Authorization = authenticationHeader;
        }

        if (_messageHandler is HttpClientHandler clientHandler && certificate != null)
        {
            clientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
            clientHandler.ClientCertificates.Clear();
            clientHandler.ClientCertificates.Add(certificate);
        }

        var response = await _messageClient
            .SendAsync(requestMessage, HttpCompletionOption.ResponseContentRead, cancellationToken)
            .ConfigureAwait(false);

        if (_messageHandler is HttpClientHandler ch)
        {
            ch.ClientCertificates.Clear();
        }

        if (!response.IsSuccessStatusCode)
        {
            if (response.Content.Headers.ContentType?.MediaType?
                .Equals("text/plain", StringComparison.OrdinalIgnoreCase) == true)
            {
                return (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false), null);
            }

            return ("Error retrieving certificate", null);
        }

        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        var contentInfo = new CmsContentInfo(reader);
        if(contentInfo.ContentType.Value != Oids.Pkcs7Signed)
        {
            throw new InvalidOperationException("Expected signed data from server");
        }
        reader = new AsnReader(contentInfo.EncodedContent, AsnEncodingRules.DER);
        var signedData = new SignedData(reader);
        return (null, new X509Certificate2Collection(signedData.Certificates ?? []));
    }

    private static CertificateRequest CreateCertificateRequest<TAlgorithm>(
        X500DistinguishedName distinguishedName,
        TAlgorithm key,
        X509KeyUsageFlags usageFlags) where TAlgorithm : AsymmetricAlgorithm
    {
        var req = key switch
        {
            RSA rsa => new CertificateRequest(
                distinguishedName,
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss),
            ECDsa ecDsa => new CertificateRequest(
                distinguishedName,
                ecDsa,
                HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException($"{typeof(TAlgorithm).FullName} is not supported")
        };
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(usageFlags, false));
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                [
                    Oids.TimeStampingPurpose.InitializeOid(Oids.TimeStampingPurposeFriendlyName),
                    Oids.ClientAuthenticationPurpose.InitializeOid(Oids.ClientAuthenticationPurposeFriendlyName),
                    Oids.ServerAuthenticationPurpose.InitializeOid(Oids.ServerAuthenticationPurposeFriendlyName)
                ],
                true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req;
    }
}
