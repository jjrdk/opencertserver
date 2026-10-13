namespace OpenCertServer.Ca.Utils.X509Extensions;

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// The certificate policies extension (RFC 5280 §4.2.1.4, OID 2.5.29.32): the policy identifiers the
/// issuing CA asserts for a certificate. Only the identifiers are written; policy qualifiers are not
/// supported, and are skipped when reading.
/// </summary>
/// <remarks>
/// <code>
/// certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
/// PolicyInformation ::= SEQUENCE {
///     policyIdentifier   CertPolicyId,
///     policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
/// CertPolicyId ::= OBJECT IDENTIFIER
/// </code>
/// </remarks>
public sealed class X509CertificatePoliciesExtension : X509Extension
{
    /// <summary>The special policy identifier anyPolicy (2.5.29.32.0), RFC 5280 §4.2.1.4.</summary>
    public const string AnyPolicy = Oids.AnyCertPolicy;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509CertificatePoliciesExtension"/> class with the given
    /// policy identifiers.
    /// </summary>
    public X509CertificatePoliciesExtension(IEnumerable<string> policyIdentifiers, bool critical = false)
        : base(new Oid(Oids.CertPolicies), Encode(policyIdentifiers), critical)
    {
        PolicyIdentifiers = Decode(RawData);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509CertificatePoliciesExtension"/> class from an encoded
    /// extension, for example one read from a certificate.
    /// </summary>
    public X509CertificatePoliciesExtension(AsnEncodedData encodedExtension, bool critical)
        : base(new Oid(Oids.CertPolicies), encodedExtension.RawData, critical)
    {
        PolicyIdentifiers = Decode(RawData);
    }

    /// <summary>Gets the policy identifiers, in the order they are encoded.</summary>
    public IReadOnlyList<string> PolicyIdentifiers { get; }

    private static byte[] Encode(IEnumerable<string> policyIdentifiers)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            var any = false;
            foreach (var policy in policyIdentifiers)
            {
                any = true;
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(policy);
                }
            }

            if (!any)
            {
                throw new ArgumentException("At least one policy identifier is required.", nameof(policyIdentifiers));
            }
        }

        return writer.Encode();
    }

    private static IReadOnlyList<string> Decode(byte[] rawData)
    {
        var policies = new List<string>();
        var sequence = new AsnReader(rawData, AsnEncodingRules.DER).ReadSequence();
        while (sequence.HasData)
        {
            var information = sequence.ReadSequence();
            policies.Add(information.ReadObjectIdentifier());
            if (information.HasData)
            {
                information.ReadEncodedValue(); // policyQualifiers - not interpreted
            }
        }

        return policies.AsReadOnly();
    }
}
