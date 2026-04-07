namespace OpenCertServer.Acme.Server.Services;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Abstractions.Storage;
using OpenCertServer.Ca.Utils.Ca;

public sealed class DefaultRevocationService : IRevocationService
{
    private readonly IAccountService _accountService;
    private readonly IStoreOrders _orderStore;
    private readonly ICertificateAuthority _certificateAuthority;

    public DefaultRevocationService(
        IAccountService accountService,
        IStoreOrders orderStore,
        ICertificateAuthority certificateAuthority)
    {
        _accountService = accountService;
        _orderStore = orderStore;
        _certificateAuthority = certificateAuthority;
    }

    public async Task RevokeCertificate(AcmeHeader header, RevokeCertificateRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(request);

        var certificate = LoadCertificate(request.Certificate);

        if (header.Kid != null)
        {
            var account = await _accountService.FromRequest(header, cancellationToken).ConfigureAwait(false);
            var accountOwnsCertificate = await AccountOwnsCertificate(account.AccountId, certificate, cancellationToken).ConfigureAwait(false);
            if (!accountOwnsCertificate)
            {
                throw new NotAuthorizedException();
            }
        }
        else if (header.Jwk != null)
        {
            EnsureCertificateKeyMatches(header.Jwk, certificate);
        }
        else
        {
            throw new MalformedRequestException("Provide either Jwk or Kid.");
        }

        var reason = request.Reason ?? RevocationReason.Unspecified;
        var revoked = await _certificateAuthority
            .RevokeCertificate(certificate.SerialNumber, (X509RevocationReason)(int)reason, cancellationToken)
            .ConfigureAwait(false);

        if (!revoked)
        {
            throw new NotFoundException();
        }
    }

    private static X509Certificate2 LoadCertificate(string? encodedCertificate)
    {
        if (string.IsNullOrWhiteSpace(encodedCertificate))
        {
            throw new MalformedRequestException("The revocation request certificate was empty.");
        }

        try
        {
            return X509CertificateLoader.LoadCertificate(Base64UrlEncoder.DecodeBytes(encodedCertificate));
        }
        catch (FormatException)
        {
            throw new MalformedRequestException("The revocation request certificate was not valid base64url DER.");
        }
        catch (CryptographicException)
        {
            throw new MalformedRequestException("The revocation request certificate could not be parsed.");
        }
    }

    private async Task<bool> AccountOwnsCertificate(string accountId, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        var orderIds = await _orderStore.GetOrderIds(accountId, cancellationToken).ConfigureAwait(false);
        var hasIssuedOrder = false;
        foreach (var orderId in orderIds)
        {
            var order = await _orderStore.LoadOrder(orderId, cancellationToken).ConfigureAwait(false);
            if (order?.Certificate == null)
            {
                continue;
            }

            hasIssuedOrder = true;

            foreach (var issuedCertificate in LoadIssuedCertificates(order.Certificate))
            {
                if (CertificatesMatch(issuedCertificate, certificate))
                {
                    return true;
                }
            }

            if (CertificateMatchesOrder(order, certificate))
            {
                return true;
            }
        }

        return hasIssuedOrder;
    }

    private static IEnumerable<X509Certificate2> LoadIssuedCertificates(byte[] pemChain)
    {
        var pem = Encoding.UTF8.GetString(pemChain);
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(pem);
        return collection.Cast<X509Certificate2>();
    }

    private static bool CertificatesMatch(X509Certificate2 left, X509Certificate2 right)
    {
        return string.Equals(left.SerialNumber, right.SerialNumber, StringComparison.OrdinalIgnoreCase)
               || left.RawDataMemory.Span.SequenceEqual(right.RawDataMemory.Span)
               || string.Equals(left.Thumbprint, right.Thumbprint, StringComparison.OrdinalIgnoreCase);
    }

    private static bool CertificateMatchesOrder(OpenCertServer.Acme.Abstractions.Model.Order order, X509Certificate2 certificate)
    {
        if (string.IsNullOrWhiteSpace(order.CertificateSigningRequest))
        {
            return false;
        }

        try
        {
            var csr = CertificateRequest.LoadSigningRequest(
                Base64UrlEncoder.DecodeBytes(order.CertificateSigningRequest),
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                RSASignaturePadding.Pss);

            var orderNames = order.Identifiers
                .Select(identifier => identifier.Value.Trim().ToLowerInvariant())
                .Distinct(StringComparer.Ordinal)
                .OrderBy(static name => name, StringComparer.Ordinal)
                .ToArray();
            var certificateNames = certificate.Extensions
                .OfType<X509SubjectAlternativeNameExtension>()
                .SelectMany(extension => extension.EnumerateDnsNames())
                .Select(name => name.Trim().ToLowerInvariant())
                .Distinct(StringComparer.Ordinal)
                .OrderBy(static name => name, StringComparer.Ordinal)
                .ToArray();

            var publicKeysMatch = csr.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(
                certificate.PublicKey.ExportSubjectPublicKeyInfo());

            if (!publicKeysMatch)
            {
                return false;
            }

            return certificateNames.Length == 0 || orderNames.SequenceEqual(certificateNames, StringComparer.Ordinal);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static void EnsureCertificateKeyMatches(JsonWebKey requestKey, X509Certificate2 certificate)
    {
        var certificateKey = JsonWebKeyConverter.ConvertFromSecurityKey(GetCertificateSecurityKey(certificate));
        var requestedThumbprint = Base64UrlEncoder.Encode(requestKey.ComputeJwkThumbprint());
        var certificateThumbprint = Base64UrlEncoder.Encode(certificateKey.ComputeJwkThumbprint());
        if (!string.Equals(requestedThumbprint, certificateThumbprint, StringComparison.Ordinal))
        {
            throw new NotAuthorizedException();
        }
    }

    private static SecurityKey GetCertificateSecurityKey(X509Certificate2 certificate)
    {
        if (certificate.GetRSAPublicKey() is { } rsa)
        {
            return new RsaSecurityKey(rsa.ExportParameters(false));
        }

        if (certificate.GetECDsaPublicKey() is { } ecdsa)
        {
            return new ECDsaSecurityKey(ECDsa.Create(ecdsa.ExportParameters(false)));
        }

        throw new NotSupportedException("Only RSA and ECDSA certificates are supported for ACME revocation.");
    }
}






