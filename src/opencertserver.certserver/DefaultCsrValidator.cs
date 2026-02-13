namespace OpenCertServer.CertServer;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using Acme.Abstractions.IssuanceServices;
using Acme.Abstractions.Model;

internal sealed class DefaultCsrValidator : ICsrValidator
{
    /// <inheritdoc />
    public Task<(bool isValid, AcmeError? error)> ValidateCsr(
        Order order,
        string csr,
        CancellationToken cancellationToken)
    {
        var req = PemEncoding.TryFind(csr, out _)
            ? CertificateRequest.LoadSigningRequestPem(csr, HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pss)
            : CertificateRequest.LoadSigningRequest(csr.Base64DecodeBytes(), HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pss);
        var hasNames = req.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().All(ext =>
            ext.EnumerateDnsNames().All(entry => order.Identifiers.Any(i => i.Value == entry)));
        return Task.FromResult((hasName: hasNames, (AcmeError?)null));
    }
}
