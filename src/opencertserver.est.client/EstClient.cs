﻿namespace OpenCertServer.Est.Client;

using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Ca.Utils;

public sealed class EstClient : IDisposable
{
    private const string TimeStamping = "1.3.6.1.5.5.7.3.8";
    private readonly Uri _estUri;
    private readonly HttpMessageHandler _messageHandler;

    public EstClient(Uri estUri, HttpMessageHandler? messageHandler = null)
    {
        if (estUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Must use HTTPS", nameof(estUri));
        }

        _estUri = estUri;
        _messageHandler = messageHandler ?? new SocketsHttpHandler();
    }

    public async Task<X509Certificate2Collection> Enroll(
        X500DistinguishedName distinguishedName,
        RSA key,
        X509KeyUsageFlags usageFlags,
        AuthenticationHeaderValue? authenticationHeader = null,
        X509Certificate2? certificate = null,
        CancellationToken cancellationToken = default)
    {
        var request = CreateCertificateRequest(distinguishedName, key, usageFlags);
        var bytes = await RequestCertBytes(request, authenticationHeader, certificate, cancellationToken).ConfigureAwait(false);
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(bytes);
        collection[^1] = collection[^1].CopyWithPrivateKey(key);
        return collection;
    }

    public async Task<X509Certificate2Collection> Enroll(
        X500DistinguishedName distinguishedName,
        ECDsa key,
        X509KeyUsageFlags usageFlags,
        AuthenticationHeaderValue? authenticationHeader = null,
        X509Certificate2? certificate = null,
        CancellationToken cancellationToken = default)
    {
        var request = CreateCertificateRequest(distinguishedName, key, usageFlags);

        var pem = await RequestCertBytes(request, authenticationHeader, certificate, cancellationToken).ConfigureAwait(false);
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(pem);
        collection[^1] = collection[^1].CopyWithPrivateKey(key);
        return collection;
    }

    public async Task<X509Certificate2Collection> ReEnroll(
        X509Certificate2 certificate,
        X509KeyUsageFlags usageFlags,
        CancellationToken cancellationToken = default)
    {
        var oidValue = certificate.PublicKey.Oid.Value;

        var certRequest = oidValue switch
        {
            CertificateConstants.EcdsaOid => CreateCertificateRequest(
                certificate.SubjectName,
                certificate.GetECDsaPrivateKey()!,
                usageFlags),
            CertificateConstants.RsaOid => CreateCertificateRequest(
                certificate.SubjectName,
                certificate.GetRSAPrivateKey()!,
                usageFlags),
            _ => throw new NotSupportedException($"{oidValue} is not supported")
        };
        var content = new StringContent(certRequest.ToPkcs10(), Encoding.UTF8, "application/pkcs10-mime");
        var requestUriBuilder = new UriBuilder(
            Uri.UriSchemeHttps,
            _estUri.Host,
            _estUri.Port,
            "/.well-known/est/simplereenroll");
        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = requestUriBuilder.Uri,
            Content = content
        };

        request.Headers.Add("X-Client-Cert", Convert.ToBase64String(certificate.GetRawCertData()));
        if (_messageHandler is HttpClientHandler clientHandler)
        {
            clientHandler.ClientCertificates.Clear();
            clientHandler.ClientCertificates.Add(certificate);
        }

        var client = new HttpClient(_messageHandler);
        var response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken)
            .ConfigureAwait(false);
        var bytes = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var s = new X509Certificate2Collection();
        s.ImportFromPem(bytes);
        s[^1] = oidValue switch
        {
            "1.2.840.10045.2.1" => s[^1].CopyWithPrivateKey(certificate.GetECDsaPrivateKey()!),
            "1.2.840.113549.1.1.1" => s[^1].CopyWithPrivateKey(certificate.GetRSAPrivateKey()!),
            _ => throw new NotSupportedException($"{oidValue} is not supported")
        };

        return s;
    }

    private async Task<string> RequestCertBytes(
        CertificateRequest request,
        AuthenticationHeaderValue? authenticationHeader = null,
        X509Certificate2? certificate = null,
        CancellationToken cancellationToken = default)
    {
        var requestUriBuilder = new UriBuilder(
            Uri.UriSchemeHttps,
            _estUri.Host,
            _estUri.Port,
            "/.well-known/est/simpleenroll");
        var requestMessage = new HttpRequestMessage
        {
            Content = new StringContent(request.ToPkcs10(), Encoding.UTF8, "application/pkcs10-mime"),
            Method = HttpMethod.Post,
            RequestUri = requestUriBuilder.Uri
        };
        if (authenticationHeader != null)
        {
            requestMessage.Headers.Authorization = authenticationHeader;
        }

        if (_messageHandler is HttpClientHandler clientHandler)
        {
            clientHandler.ClientCertificates.Clear();
            if (certificate != null)
            {
                clientHandler.ClientCertificates.Add(certificate);
            }
        }

        var client = new HttpClient(_messageHandler);
        var response = await client.SendAsync(requestMessage, HttpCompletionOption.ResponseContentRead, cancellationToken)
            .ConfigureAwait(false);
        var bytes = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return bytes;
    }

    private static CertificateRequest CreateCertificateRequest(
        X500DistinguishedName distinguishedName,
        RSA rsa,
        X509KeyUsageFlags usageFlags)
    {
        var req = new CertificateRequest(
            distinguishedName,
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss)
        {
            CertificateExtensions =
            {
                new X509BasicConstraintsExtension(false, false, 0, false),
                new X509KeyUsageExtension(usageFlags, false),
                new X509EnhancedKeyUsageExtension([new(TimeStamping)], true)
            }
        };

        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req;
    }

    private static CertificateRequest CreateCertificateRequest(
        X500DistinguishedName distinguishedName,
        ECDsa ecDsa,
        X509KeyUsageFlags usageFlags)
    {
        var req = new CertificateRequest(
            distinguishedName,
            ecDsa,
            HashAlgorithmName.SHA256)
        {
            CertificateExtensions =
            {
                new X509BasicConstraintsExtension(false, false, 0, false),
                new X509KeyUsageExtension(usageFlags, false),
                new X509EnhancedKeyUsageExtension([new(TimeStamping)], true)
            }
        };

        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _messageHandler.Dispose();
    }
}
