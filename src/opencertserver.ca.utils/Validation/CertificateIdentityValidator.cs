using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Validation;

/// <summary>
/// Verifies that the <c>subjectAltName</c> of a TLS/DTLS certificate presents the identity of the
/// application service a client is trying to reach, per RFC 9525 (which obsoletes RFC 6125). This is
/// the "hostname verification" step, generalized to non-DNS identifiers.
///
/// <para>
/// <b>Scope.</b> RFC 9525 governs <em>identity matching</em> in the leaf end-entity certificate. It
/// deliberately does <em>not</em> build or verify the PKIX path to a trust anchor, check validity dates,
/// or check revocation — those are the job of RFC 5280 / OCSP / CRL. A production caller MUST combine
/// this matcher with a full PKIX path validation; using it alone is not sufficient.
/// </para>
///
/// <para>
/// <b>Dependency.</b> The acceptable reference identifiers for the requested service are supplied by an
/// injected <see cref="ILookUpServiceProvider"/>. Keeping them behind an interface (with no concrete
/// implementation here) is what makes the algorithm unit-testable with a mock lookup.
/// </para>
///
/// <para>
/// <b>No common-name fallback.</b> RFC 9525 requires the identifier to be present in
/// <c>subjectAltName</c>. A certificate that presents no <c>subjectAltName</c> entry fails with
/// <see cref="CertificateIdentityValidationFailure.MissingSubjectAlternativeName"/>; the subject
/// / common name is <em>never</em> consulted.
/// </para>
/// </summary>
public sealed class CertificateIdentityValidator
{
    private readonly ILookUpServiceProvider _lookup;

    /// <summary>
    /// Creates a validator that resolves acceptable reference identifiers via <paramref name="lookup"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="lookup"/> is null.</exception>
    public CertificateIdentityValidator(ILookUpServiceProvider lookup)
    {
        ArgumentNullException.ThrowIfNull(lookup);
        _lookup = lookup;
    }

    /// <summary>
    /// Verifies that <paramref name="certificate"/> presents at least one identifier acceptable for the
    /// requested <paramref name="reference"/> service, following the RFC 9525 verification algorithm.
    /// </summary>
    /// <param name="reference">The service identity the client intends to reach.</param>
    /// <param name="certificate">The leaf (end-entity) certificate presented by the server.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// A <see cref="CertificateIdentityValidationResult"/> with <see cref="CertificateIdentityValidationResult.IsMatch"/>
    /// set when a presented identifier matches a reference; otherwise the identifying
    /// <see cref="CertificateIdentityValidationFailure"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="reference"/> or
    /// <paramref name="certificate"/> is null.</exception>
    public async Task<CertificateIdentityValidationResult> Validate(
        ServiceIdentity reference,
        X509Certificate2 certificate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reference);
        ArgumentNullException.ThrowIfNull(certificate);

        // RFC 9525 §4.1 / §6.1: the identifier is carried only in subjectAltName. We never fall back
        // to the common name / subject, which is the central security change from RFC 6125.
        var presented = ExtractPresented(certificate);
        if (presented.Count == 0)
        {
            return CertificateIdentityValidationResult.Unmatched(
                CertificateIdentityValidationFailure.MissingSubjectAlternativeName);
        }

        // RFC 9525 §4.3.1: build the list of acceptable reference identifiers independently of what the
        // server presents.
        var references = await _lookup
            .ResolveServiceIdentities(reference, cancellationToken)
            .ConfigureAwait(false);
        if (references.Count == 0)
        {
            return CertificateIdentityValidationResult.Unmatched(
                CertificateIdentityValidationFailure.NoReferenceIdentities);
        }

        // RFC 9525 §4.3.3: match each acceptable reference identifier against the presented ones.
        foreach (var referenceId in references)
        {
            foreach (var presentedId in presented)
            {
                if (IdentityMatcher.Matches(referenceId, presentedId))
                {
                    // RFC 9525 §4.3.4: a match found -> success; the client MUST use the matched
                    // reference identifier as the validated identity.
                    return CertificateIdentityValidationResult.Matched(referenceId);
                }
            }
        }

        // RFC 9525 §4.3.4: no match found -> failure.
        return CertificateIdentityValidationResult.Unmatched(CertificateIdentityValidationFailure.NoMatch);
    }

    /// <summary>
    /// Extracts the presentable identifiers from a certificate's <c>subjectAltName</c> extension,
    /// which is the only source of an RFC 9525 / RFC 6125 identity. DNS (<c>dNSName</c>), IP
    /// (<c>iPAddress</c>) and URI (<c>uniformResourceIdentifier</c>) identifiers are supported
    /// directly. SRV (<c>SRVName</c> <c>otherName</c>) requires application-specific presentation and
    /// is exercised via <see cref="IdentityMatcher"/> rather than parsed from a raw <c>otherName</c>
    /// here.
    /// </summary>
    private static IReadOnlyList<ServiceIdentity> ExtractPresented(X509Certificate2 certificate)
    {
        // OID 2.5.29.17, the subjectAltName extension. When it is absent the certificate presents no
        // acceptable identifier and the caller must fail (never fall back to the subject / CN).
        var sanExtension = certificate.Extensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .FirstOrDefault();
        if (sanExtension is null || sanExtension.RawData.Length == 0)
        {
            return [];
        }

        var generalNames = new GeneralNames(new AsnReader(sanExtension.RawData, AsnEncodingRules.DER));
        var identities = generalNames.Names.Select(generalName =>
        {
            return generalName.Type switch
            {
                GeneralName.GeneralNameType.DnsName => ServiceIdentity.Dns(generalName.Value.ToString()!),
                GeneralName.GeneralNameType.IpAddress => ServiceIdentity.Ip(
                    ParseIpAddress(generalName.Value as AsnOctetString)),
                GeneralName.GeneralNameType.UniformResourceIdentifier => ServiceIdentity.Uri(
                    generalName.Value.ToString()!),
                GeneralName.GeneralNameType.OtherName =>
                    generalName.Value is OtherName { TypeId: Oids.DnsSrvOid } other
                        ? ServiceIdentity.Srv(other.StringValue!)
                        : null,
                // otherName, rfc822Name, x400Address, directoryName, ediPartyName and
                _ => null
            };

            static string ParseIpAddress(AsnOctetString? value)
            {
                return value is null
                    ? throw new InvalidOperationException("IP address SAN value is null")
                    : new IPAddress(value.Value).ToString();
            }
        }).Where(identity => identity is not null).ToList();
        return [.. identities.OfType<ServiceIdentity>()];
    }
}
