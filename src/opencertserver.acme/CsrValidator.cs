namespace OpenCertServer.Acme;

using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertesSlim.Acme;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509Extensions;

/// <summary>
/// The default ACME CSR validator used by a standalone ACME host. It checks that the proof-of-possession
/// CSR carries at least one DNS subjectAltName and that its identifiers exactly match the order's
/// identifiers. Scope authority remains with the backing CA, which re-checks scope on the delegated
/// request.
/// </summary>
public sealed class DefaultCsrValidator : ICsrValidator
{
    /// <inheritdoc />
    public Task<(bool isValid, AcmeError? error)> ValidateCsr(
        Order order,
        string csr,
        CancellationToken cancellationToken)
    {
        try
        {
            var request = PemEncoding.TryFind(csr, out _)
                ? CertificateRequest.LoadSigningRequestPem(csr, HashAlgorithmName.SHA256,
                    CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pss)
                : CertificateRequest.LoadSigningRequest(csr.Base64DecodeBytes(), HashAlgorithmName.SHA256,
                    CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pss);

            var csrNames = request.CertificateExtensions
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
        catch (CryptographicException exception)
        {
            return Task.FromResult(Invalid($"The CSR could not be parsed: {exception.Message}"));
        }
        catch (ArgumentException exception)
        {
            return Task.FromResult(Invalid($"The CSR could not be parsed: {exception.Message}"));
        }

        static (bool isValid, AcmeError? error) Invalid(string detail)
            => (false, new AcmeError { Type = "badCSR", Detail = detail });
    }
}
