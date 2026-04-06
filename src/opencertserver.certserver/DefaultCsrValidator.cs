namespace OpenCertServer.CertServer;

using System.Globalization;
using System.Linq;
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
        try
        {
            var req = PemEncoding.TryFind(csr, out _)
                ? CertificateRequest.LoadSigningRequestPem(csr, HashAlgorithmName.SHA256,
                    CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pss)
                : CertificateRequest.LoadSigningRequest(csr.Base64DecodeBytes(), HashAlgorithmName.SHA256,
                    CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pss);

            var csrNames = req.CertificateExtensions
                .OfType<X509SubjectAlternativeNameExtension>()
                .SelectMany(ext => ext.EnumerateDnsNames())
                .Select(name => name.Trim().ToLowerInvariant())
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (csrNames.Length == 0)
            {
                return Task.FromResult(Invalid("The CSR must contain at least one DNS subjectAltName entry."));
            }

            var orderNames = order.Identifiers
                .Select(identifier => identifier.Value.Trim().ToLowerInvariant())
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (!csrNames.OrderBy(static x => x, StringComparer.Ordinal)
                    .SequenceEqual(orderNames.OrderBy(static x => x, StringComparer.Ordinal), StringComparer.Ordinal))
            {
                return Task.FromResult(Invalid(
                    string.Format(
                        CultureInfo.InvariantCulture,
                        "The CSR identifiers must exactly match the order identifiers. CSR: [{0}] Order: [{1}]",
                        string.Join(", ", csrNames),
                        string.Join(", ", orderNames))));
            }

            return Task.FromResult((true, (AcmeError?)null));
        }
        catch (CryptographicException ex)
        {
            return Task.FromResult(Invalid($"The CSR could not be parsed: {ex.Message}"));
        }
        catch (ArgumentException ex)
        {
            return Task.FromResult(Invalid($"The CSR could not be parsed: {ex.Message}"));
        }

        static (bool isValid, AcmeError? error) Invalid(string detail)
            => (false, new AcmeError("badCSR", detail));
    }
}
