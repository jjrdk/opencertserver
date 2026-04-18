namespace OpenCertServer.Est.Client;

using System;
using System.Formats.Asn1;
using System.Globalization;
using System.Net;
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
using OpenCertServer.Ca.Utils.X509Extensions;

/// <summary>
/// Defines an EST client for enrolling and re-enrolling certificates.
/// </summary>
public sealed class EstClient : IDisposable
{
    private const int MaxRedirects = 10;
    private static readonly HttpMethod HeadMethod = new("HEAD");
    private readonly Uri _estHost;
    private readonly string? _profileName;
    private readonly EstClientOptions _options;
    private readonly bool _ownsMessageHandler;
    private HttpMessageHandler _messageHandler;
    private HttpClient _messageClient;
    private readonly AsyncLocal<HttpRequestMessage?> _activeRequest = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="EstClient"/> class.
    /// </summary>
    /// <param name="estHost">The <see cref="Uri"/> of the EST server.</param>
    /// <param name="options">The client options.</param>
    /// <param name="profileName">The optional profile name to use for the EST server.</param>
    /// <param name="messageHandler">The optional <see cref="HttpMessageHandler"/> for handling server requests.</param>
    /// <exception cref="ArgumentException">Thrown if the <see cref="Uri"/> scheme of the server is not HTTPS.</exception>
    public EstClient(
        Uri estHost,
        EstClientOptions? options,
        string? profileName = null,
        HttpMessageHandler? messageHandler = null)
    {
        if (estHost.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Must use HTTPS", nameof(estHost));
        }

        _estHost = estHost;
        _profileName = profileName;
        _options = options ?? new EstClientOptions();
        _ownsMessageHandler = messageHandler == null;
        _messageHandler = messageHandler ?? new SocketsHttpHandler();
        _messageClient = CreateHttpClient(_messageHandler);
    }

    /// <summary>
    /// Gets the pending trust material retrieved during EST bootstrap.
    /// </summary>
    public EstBootstrapTrust? PendingBootstrapTrust { get; private set; }

    /// <summary>
    /// Accepts the pending EST bootstrap trust material for subsequent explicit trust validation.
    /// </summary>
    public void AcceptBootstrapTrust()
    {
        if (PendingBootstrapTrust == null)
        {
            throw new InvalidOperationException("No pending EST bootstrap trust is available to accept.");
        }

        foreach (var certificate in PendingBootstrapTrust.Certificates.Where(certificate => _options
            .ExplicitTrustAnchors
            .All(existing => !existing.RawData.AsSpan().SequenceEqual(certificate.RawData))))
        {
            _options.ExplicitTrustAnchors.Add(certificate);
        }

        PendingBootstrapTrust = null;
        ResetTransportSession();
    }

    /// <summary>
    /// Rejects the pending EST bootstrap trust material.
    /// </summary>
    public void RejectBootstrapTrust()
    {
        PendingBootstrapTrust = null;
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
        CopyReEnrollmentIdentityExtensions(certificate, certRequest);

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

        using var request = new HttpRequestMessage(HttpMethod.Get, requestUriBuilder.Uri);
        EnsureBootstrapRequestAllowed(request, authenticationHeader: null, clientCertificate: null);
        var response =
            await SendWithRedirectHandlingAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken)
                .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw await CreateEstErrorAsync(response, "Error retrieving CA certificates", cancellationToken)
                .ConfigureAwait(false);
        }

        var b64 = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var bytes = Convert.FromBase64String(b64);
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        var contentInfo = new CmsContentInfo(reader);
        if (contentInfo.ContentType.Value != Oids.Pkcs7Signed)
        {
            throw new InvalidOperationException("Expected signed data from server");
        }

        reader = new AsnReader(contentInfo.EncodedContent, AsnEncodingRules.DER);
        var signedData = new SignedData(reader);
        var certificates = new X509Certificate2Collection(signedData.Certificates ?? []);
        CaptureBootstrapTrustIfNeeded(request.RequestUri!, certificates);
        return certificates;
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
        EnsureBootstrapRequestAllowed(request, authenticationHeader, clientCertificate: null);
        var response =
            await SendWithRedirectHandlingAsync(request, HttpCompletionOption.ResponseHeadersRead,
                    CancellationToken.None)
                .ConfigureAwait(false);
        if (response.StatusCode is HttpStatusCode.NoContent or HttpStatusCode.NotFound)
        {
            return new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null);
        }

        response = response.EnsureSuccessStatusCode();
        var responseText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        byte[] bytes;
        try
        {
            bytes = responseText.Base64DecodeBytes();
        }
        catch (FormatException)
        {
            bytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            bytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        }

        var reader = new AsnReader(bytes, AsnEncodingRules.DER,
            new AsnReaderOptions { SkipSetSortOrderVerification = true });

        try
        {
            var csrAttributes = new CertificateSigningRequestTemplate(new AsnReader(bytes, AsnEncodingRules.DER,
                new AsnReaderOptions { SkipSetSortOrderVerification = true }));
            return csrAttributes;
        }
        catch (Exception)
        {
            var csrAttributes = new CsrAttributes(reader);
            return csrAttributes.GetPreferredTemplate() ??
                new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null);
        }
    }

    private void ConfigureServerCertificateValidation(HttpMessageHandler handler, EstClientOptions options)
    {
        switch (handler)
        {
            case SocketsHttpHandler sockets:
                sockets.SslOptions.RemoteCertificateValidationCallback =
                    (_, cert, chain, _) =>
                        ValidateServerCertificate(cert as X509Certificate2, chain, options);
                return;
            case HttpClientHandler httpClientHandler:
                httpClientHandler.ServerCertificateCustomValidationCallback =
                    (_, certificate, chain, _) =>
                        ValidateServerCertificate(certificate, chain, options);
                break;
        }
    }

    private static void ConfigureRedirectHandling(HttpMessageHandler handler)
    {
        switch (handler)
        {
            case SocketsHttpHandler sockets:
                sockets.AllowAutoRedirect = false;
                break;
            case HttpClientHandler httpClientHandler:
                httpClientHandler.AllowAutoRedirect = false;
                break;
        }
    }

    private bool ValidateServerCertificate(
        X509Certificate2? certificate,
        X509Chain? _,
        EstClientOptions options)
    {
        if (certificate == null)
        {
            return false;
        }

        return options.TrustAnchorMode switch
        {
            EstTrustAnchorMode.ExplicitOnly => ExplicitTrustAuthorization(),
            EstTrustAnchorMode.ImplicitOnly => ImplicitTrustAuthorization(),
            EstTrustAnchorMode.ExplicitThenImplicit => ExplicitTrustAuthorization() || ImplicitTrustAuthorization(),
            _ => throw new InvalidOperationException($"Unsupported trust anchor mode: {options.TrustAnchorMode}")
        } || IsBootstrapCaCertificatesRequestAllowed(certificate, options);

        bool ExplicitTrustAuthorization()
        {
            if (options.ExplicitTrustAnchors.Count > 0 &&
                BuildChainWithExplicitTrustAnchors(certificate, options))
            {
                return AuthorizeServerIdentity(certificate, GetAuthorizedUri(options));
            }

            return false;
        }

        bool ImplicitTrustAuthorization()
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = options.RevocationMode;
            chain.ChainPolicy.RevocationFlag = options.RevocationFlag;

            return chain.Build(certificate)
             && AuthorizeServerIdentity(certificate, GetAuthorizedUri(options));
        }
    }

    private bool IsBootstrapCaCertificatesRequestAllowed(X509Certificate2 certificate, EstClientOptions options)
    {
        if (!options.AllowBootstrapCaCertsWithoutTrustedServer ||
            options.TrustAnchorMode != EstTrustAnchorMode.ExplicitOnly ||
            options.ExplicitTrustAnchors.Count != 0 ||
            PendingBootstrapTrust != null)
        {
            return false;
        }

        var request = _activeRequest.Value;
        if (request is not { Method: { } method, RequestUri: { } requestUri } ||
            method != HttpMethod.Get && method != HeadMethod)
        {
            return false;
        }

        if (request.Headers.Authorization != null)
        {
            return false;
        }

        var path = requestUri.AbsolutePath;
        var isBootstrapPath = string.Equals(path, "/.well-known/est/cacerts", StringComparison.Ordinal) ||
            string.Equals(path, "/.well-known/est/fullcmc", StringComparison.Ordinal) ||
            (path.StartsWith("/.well-known/est/", StringComparison.Ordinal) &&
                (path.EndsWith("/cacerts", StringComparison.Ordinal) ||
                    path.EndsWith("/fullcmc", StringComparison.Ordinal)));

        return isBootstrapPath && AuthorizeServerIdentity(certificate, requestUri);
    }

    private Uri GetAuthorizedUri(EstClientOptions options)
    {
        return _activeRequest.Value?.RequestUri ?? options.AuthorizedUri ?? _estHost;
    }

    private void CaptureBootstrapTrustIfNeeded(Uri requestUri, X509Certificate2Collection certificates)
    {
        if (!ShouldCaptureBootstrapTrust(requestUri) || certificates.Count == 0)
        {
            return;
        }

        PendingBootstrapTrust = new EstBootstrapTrust(requestUri, certificates);
    }

    private bool ShouldCaptureBootstrapTrust(Uri requestUri)
    {
        return _options is
            {
                AllowBootstrapCaCertsWithoutTrustedServer: true, TrustAnchorMode: EstTrustAnchorMode.ExplicitOnly,
                ExplicitTrustAnchors.Count: 0
            } &&
            PendingBootstrapTrust == null &&
            IsBootstrapPath(requestUri.AbsolutePath);
    }

    private void EnsureBootstrapRequestAllowed(
        HttpRequestMessage request,
        AuthenticationHeaderValue? authenticationHeader,
        X509Certificate2? clientCertificate)
    {
        var path = request.RequestUri?.AbsolutePath ?? string.Empty;

        if (PendingBootstrapTrust != null)
        {
            throw new InvalidOperationException(
                "EST bootstrap trust is pending. No other EST protocol exchange is allowed until the trust response is accepted and a new TLS session is established.");
        }

        if (!IsBootstrapProvisioningRequired())
        {
            return;
        }

        var isBootstrapPath = IsBootstrapPath(path);

        if (!isBootstrapPath)
        {
            throw new InvalidOperationException(
                "EST bootstrap requires retrieving trust anchors from '/cacerts' or '/fullcmc' before any other EST protocol exchange can continue.");
        }

        if (authenticationHeader != null || clientCertificate != null)
        {
            throw new InvalidOperationException(
                "EST bootstrap requests must not answer HTTP authentication challenges or present client certificates on the provisional unauthenticated connection.");
        }
    }

    private bool IsBootstrapProvisioningRequired()
    {
        return _options is
        {
            AllowBootstrapCaCertsWithoutTrustedServer: true, TrustAnchorMode: EstTrustAnchorMode.ExplicitOnly,
            ExplicitTrustAnchors.Count: 0
        };
    }

    private static bool IsBootstrapPath(string path)
    {
        return string.Equals(path, "/.well-known/est/cacerts", StringComparison.Ordinal) ||
            string.Equals(path, "/.well-known/est/fullcmc", StringComparison.Ordinal) ||
            (path.StartsWith("/.well-known/est/", StringComparison.Ordinal) &&
                (path.EndsWith("/cacerts", StringComparison.Ordinal) ||
                    path.EndsWith("/fullcmc", StringComparison.Ordinal)));
    }

    private static bool BuildChainWithExplicitTrustAnchors(X509Certificate2 certificate, EstClientOptions options)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Clear();

        foreach (var anchor in options.ExplicitTrustAnchors)
        {
            chain.ChainPolicy.CustomTrustStore.Add(anchor);
        }

        chain.ChainPolicy.RevocationMode = options.RevocationMode;
        chain.ChainPolicy.RevocationFlag = options.RevocationFlag;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        return chain.Build(certificate);
    }

    private static bool AuthorizeServerIdentity(X509Certificate2 certificate, Uri uri)
    {
        var host = uri.IdnHost;

        if (Uri.CheckHostName(host) == UriHostNameType.IPv4 ||
            Uri.CheckHostName(host) == UriHostNameType.IPv6)
        {
            return IPAddress.TryParse(host, out var expectedIp) &&
                certificate.GetSubjectAlternativeIpAddresses().Any(ip => ip.Equals(expectedIp));
        }

        var sanDnsNames = certificate.GetSubjectAlternativeDnsNames();
        if (sanDnsNames.Count > 0)
        {
            return sanDnsNames.Any(name => DnsNameMatches(host, name));
        }

        var commonName = certificate.GetNameInfo(X509NameType.DnsName, false);
        return !string.IsNullOrWhiteSpace(commonName) && DnsNameMatches(host, commonName);
    }

    private static bool DnsNameMatches(string host, string pattern)
    {
        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(pattern))
        {
            return false;
        }

        host = NormalizeDnsName(host);
        pattern = NormalizeDnsName(pattern);

        if (string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!pattern.StartsWith("*.", StringComparison.Ordinal) || pattern.IndexOf('*', 1) >= 0)
        {
            return false;
        }

        var domain = pattern[2..];
        if (!domain.Contains('.', StringComparison.Ordinal))
        {
            return false;
        }

        var suffix = pattern[1..];
        if (!host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var prefix = host[..^suffix.Length];
        return prefix.Length > 0 && prefix.IndexOf('.') < 0;
    }

    private static string NormalizeDnsName(string value)
    {
        var normalized = value.Trim().TrimEnd('.');
        var idn = new IdnMapping();
        return idn.GetAscii(normalized).ToLowerInvariant();
    }

    private static void CopyReEnrollmentIdentityExtensions(X509Certificate2 certificate, CertificateRequest certRequest)
    {
        var subjectAlternativeName = certificate.Extensions.FirstOrDefault(x => x.Oid?.Value == Oids.SubjectAltName);
        if (subjectAlternativeName != null)
        {
            certRequest.CertificateExtensions.Add(
                new X509Extension(
                    new Oid(subjectAlternativeName.Oid!.Value!, subjectAlternativeName.Oid.FriendlyName),
                    subjectAlternativeName.RawData,
                    subjectAlternativeName.Critical));
        }
    }

    private async Task<(string?, X509Certificate2Collection?)> RequestReEnrollCerts(
        X509Certificate2 certificate,
        CertificateRequest certRequest,
        CancellationToken cancellationToken)
    {
        var content = new StringContent(certRequest.ToPkcs10Pem(), Encoding.UTF8, "application/pkcs10-mime");
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
        EnsureBootstrapRequestAllowed(request, authenticationHeader: null, clientCertificate: certificate);
        if (_messageHandler is HttpClientHandler clientHandler)
        {
            clientHandler.ClientCertificates.Clear();
            clientHandler.ClientCertificates.Add(certificate);
        }

        var response =
            await SendWithRedirectHandlingAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken)
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

        var b64 = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var bytes = b64.Base64DecodeBytes();
        var reader = new AsnReader(bytes, AsnEncodingRules.DER,
            new AsnReaderOptions { SkipSetSortOrderVerification = true });
        var contentInfo = new CmsContentInfo(reader);
        if (contentInfo.ContentType.Value != Oids.Pkcs7Signed)
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
            Content =
                new StringContent(request.ToPkcs10Base64(), Encoding.UTF8, "application/pkcs10"),
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

        EnsureBootstrapRequestAllowed(requestMessage, authenticationHeader, certificate);

        if (_messageHandler is HttpClientHandler clientHandler && certificate != null)
        {
            clientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
            clientHandler.ClientCertificates.Clear();
            clientHandler.ClientCertificates.Add(certificate);
        }

        var response = await SendWithRedirectHandlingAsync(requestMessage, HttpCompletionOption.ResponseContentRead,
                cancellationToken)
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

        var b64 = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var bytes = b64.Base64DecodeBytes();
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        var contentInfo = new CmsContentInfo(reader);
        if (contentInfo.ContentType.Value != Oids.Pkcs7Signed)
        {
            throw new InvalidOperationException("Expected signed data from server");
        }

        reader = new AsnReader(contentInfo.EncodedContent, AsnEncodingRules.DER);
        var signedData = new SignedData(reader);
        return (null, new X509Certificate2Collection(signedData.Certificates ?? []));
    }

    private async Task<HttpResponseMessage> SendWithRedirectHandlingAsync(
        HttpRequestMessage request,
        HttpCompletionOption completionOption,
        CancellationToken cancellationToken)
    {
        var currentRequest = request;
        for (var redirectCount = 0; redirectCount <= MaxRedirects; redirectCount++)
        {
            _activeRequest.Value = currentRequest;
            var response = await _messageClient.SendAsync(currentRequest, completionOption, cancellationToken)
                .ConfigureAwait(false);
            _activeRequest.Value = null;
            if (!IsRedirect(response.StatusCode) || response.Headers.Location == null)
            {
                return response;
            }

            var redirectUri = response.Headers.Location.IsAbsoluteUri
                ? response.Headers.Location
                : new Uri(currentRequest.RequestUri!, response.Headers.Location);

            if (!IsSameOrigin(currentRequest.RequestUri!, redirectUri))
            {
                response.Dispose();
                throw new InvalidOperationException(
                    $"Redirect to '{redirectUri}' requires user input. EST only follows same-origin redirects automatically.");
            }

            // Follow same-origin redirects without user input. A redirected origin would require a new TLS
            // connection and repeating all security checks, so those redirects are rejected above.
            var nextRequest =
                await CloneRequestAsync(currentRequest, redirectUri, response.StatusCode, cancellationToken)
                    .ConfigureAwait(false);
            response.Dispose();
            currentRequest = nextRequest;
        }

        throw new InvalidOperationException($"Too many EST redirects (>{MaxRedirects}).");
    }

    private static bool IsRedirect(HttpStatusCode statusCode)
    {
        return statusCode is HttpStatusCode.Moved or HttpStatusCode.Redirect or HttpStatusCode.RedirectMethod or
            HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;
    }

    private static bool IsSameOrigin(Uri currentUri, Uri redirectUri)
    {
        return string.Equals(currentUri.Scheme, redirectUri.Scheme, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(currentUri.Host, redirectUri.Host, StringComparison.OrdinalIgnoreCase) &&
            currentUri.Port == redirectUri.Port;
    }

    private static async Task<HttpRequestMessage> CloneRequestAsync(
        HttpRequestMessage request,
        Uri requestUri,
        HttpStatusCode redirectStatusCode,
        CancellationToken cancellationToken)
    {
        var method = redirectStatusCode == HttpStatusCode.RedirectMethod
            ? request.Method == HttpMethod.Head ? HttpMethod.Head : HttpMethod.Get
            : request.Method;

        var clone = new HttpRequestMessage(method, requestUri)
        {
            Version = request.Version,
            VersionPolicy = request.VersionPolicy
        };

        foreach (var header in request.Headers)
        {
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        if (method == HttpMethod.Get || method == HttpMethod.Head || request.Content == null)
        {
            return clone;
        }

        var contentBytes = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var contentClone = new ByteArrayContent(contentBytes);
        foreach (var header in request.Content.Headers)
        {
            contentClone.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        clone.Content = contentClone;

        return clone;
    }

    private static async Task<InvalidOperationException> CreateEstErrorAsync(
        HttpResponseMessage response,
        string defaultMessage,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentType?.MediaType?.Equals("text/plain", StringComparison.OrdinalIgnoreCase) ==
            true)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(error))
            {
                return new InvalidOperationException(error);
            }
        }

        return new InvalidOperationException($"{defaultMessage} (HTTP {(int)response.StatusCode}).");
    }

    private HttpClient CreateHttpClient(HttpMessageHandler handler)
    {
        ConfigureRedirectHandling(handler);
        ConfigureServerCertificateValidation(handler, _options);
        return new HttpClient(handler, disposeHandler: false);
    }

    private void ResetTransportSession()
    {
        _messageClient.Dispose();

        if (!_ownsMessageHandler)
        {
            _messageClient = CreateHttpClient(_messageHandler);
            return;
        }

        if (_messageHandler is SocketsHttpHandler)
        {
            _messageHandler.Dispose();
            _messageHandler = new SocketsHttpHandler();
        }
        else if (_messageHandler is HttpClientHandler)
        {
            _messageHandler.Dispose();
            _messageHandler = new HttpClientHandler();
        }

        _messageClient = CreateHttpClient(_messageHandler);
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
