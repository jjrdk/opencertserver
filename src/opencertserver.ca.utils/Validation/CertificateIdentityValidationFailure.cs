namespace OpenCertServer.Ca.Utils.Validation;

/// <summary>Why a certificate failed RFC 9525 service-identity validation.</summary>
public enum CertificateIdentityValidationFailure
{
    /// <summary>
    /// The presented certificate carries no <c>subjectAltName</c> entry. RFC 9525 mandates that the
    /// identifier be carried <em>only</em> in <c>subjectAltName</em>; there is no fallback to the
    /// common name / subject (the central change from RFC 6125 and the root of several MITM CVEs).
    /// </summary>
    MissingSubjectAlternativeName,

    /// <summary>
    /// The reference service resolved, via the <see cref="ILookUpServiceProvider"/>, to no acceptable
    /// reference identifiers.
    /// </summary>
    NoReferenceIdentities,

    /// <summary>
    /// The certificate presented one or more identifiers, but none matched any acceptable reference
    /// identifier.
    /// </summary>
    NoMatch
}