using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509.Templates;

namespace OpenCertServer.Est.Client;

using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ca.Utils;

/// <summary>
/// Defines an EST client for enrolling and re-enrolling certificates.
/// </summary>
public sealed class EstClient : IDisposable
{
    private readonly Uri _estHost;
    private readonly string? _profileName;
    private readonly HttpMessageHandler _messageHandler;

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
    public async Task<(string?, X509Certificate2Collection?)> Enroll<TAlgorithm>(
        X500DistinguishedName distinguishedName,
        TAlgorithm key,
        X509KeyUsageFlags usageFlags,
        AuthenticationHeaderValue? authenticationHeader = null,
        X509Certificate2? certificate = null,
        CancellationToken cancellationToken = default) where TAlgorithm : AsymmetricAlgorithm
    {
        var request = CreateCertificateRequest(distinguishedName, key, usageFlags);
        var bytes = await RequestCertBytes(_profileName, request, authenticationHeader, certificate, cancellationToken)
            .ConfigureAwait(false);
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(bytes);
        return collection.Count == 0 ? (bytes, null) : (null, collection);
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
    public async Task<X509Certificate2Collection> ReEnroll<TAlgorithm>(
        TAlgorithm key,
        X509Certificate2 certificate,
        CancellationToken cancellationToken = default) where TAlgorithm : AsymmetricAlgorithm
    {
        var certRequest = CreateCertificateRequest(
            certificate.SubjectName,
            key,
            certificate.Extensions.OfType<X509KeyUsageExtension>()
                .Aggregate(X509KeyUsageFlags.None, (flags, ext) => flags | ext.KeyUsages));

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
            Content = content,
            Headers = { Accept = { new MediaTypeWithQualityHeaderValue("application/x-pem-file") } }
        };

        request.Headers.Add("X-Client-Cert", Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));
        if (_messageHandler is HttpClientHandler clientHandler)
        {
            clientHandler.ClientCertificates.Clear();
            clientHandler.ClientCertificates.Add(certificate);
        }

        var client = new HttpClient(_messageHandler);
        var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Re-enroll failed with status code {response.StatusCode} and message: {await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)}");
        }

        var bytes = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var s = new X509Certificate2Collection();
        s.ImportFromPem(bytes);

        return s;
    }

    public async Task<X509Certificate2Collection> ServerCertificates(CancellationToken cancellationToken = default)
    {
        var pathValue = _profileName == null ? "/.well-known/est/cacert" : $"/.well-known/est/{_profileName}/cacert";
        var requestUriBuilder = new UriBuilder(
            Uri.UriSchemeHttps,
            _estHost.Host,
            _estHost.Port,
            pathValue);

        var client = new HttpClient(_messageHandler);
        var response = await client
            .GetAsync(requestUriBuilder.Uri, HttpCompletionOption.ResponseContentRead, cancellationToken)
            .ConfigureAwait(false);
        var bytes = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var coll = new X509Certificate2Collection();
        coll.ImportFromPem(bytes);
        return coll;
    }

    private async Task<string> RequestCertBytes(
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
                TransferEncoding = { new TransferCodingHeaderValue("base64") },
                Accept = { new MediaTypeWithQualityHeaderValue("application/x-pem-file") }
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

        var client = new HttpClient(_messageHandler);
        var response = await client
            .SendAsync(requestMessage, HttpCompletionOption.ResponseContentRead, cancellationToken)
            .ConfigureAwait(false);
        var bytes = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return bytes;
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

    /// <inheritdoc />
    public void Dispose()
    {
        _messageHandler.Dispose();
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

        var client = new HttpClient(_messageHandler);
        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Get,
            RequestUri = requestUriBuilder.Uri
        };
        request.Headers.Authorization = authenticationHeader;
        var response = await client
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
            .ConfigureAwait(false);
        response = response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        return new CertificateSigningRequestTemplate(new AsnReader(bytes, AsnEncodingRules.DER,
            new AsnReaderOptions { SkipSetSortOrderVerification = true }));
    }
}
