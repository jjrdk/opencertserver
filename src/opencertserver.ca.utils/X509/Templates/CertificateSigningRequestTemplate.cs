namespace OpenCertServer.Ca.Utils.X509.Templates;

using System.Formats.Asn1;
using System.Numerics;

/// <summary>
/// Defines a template for a Certificate Signing Request (CSR) as per RFC 4211.
/// </summary>
/// <code>
/// CertificationRequestInfoTemplate ::= SEQUENCE {
///   version INTEGER { v1(0) } (v1, ... ),
///   subject NameTemplate OPTIONAL,
///   subjectPKInfo [0] SubjectPublicKeyInfoTemplate {{ PKInfoAlgorithms }} OPTIONAL,
///   attributes [1] Attributes{{ CRIAttributes }}
/// }
/// </code>
public class CertificateSigningRequestTemplate : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSigningRequestTemplate"/> class.
    /// </summary>
    /// <param name="subject">The <see cref="NameTemplate"/> of the subject.</param>
    /// <param name="subjectPkInfo">The optional <see cref="SubjectPublicKeyInfoTemplate"/>.</param>
    /// <param name="attributes">The optional CRI attribute requirements.</param>
    public CertificateSigningRequestTemplate(
        NameTemplate? subject = null,
        SubjectPublicKeyInfoTemplate? subjectPkInfo = null,
        IEnumerable<CsrAttribute>? attributes = null)
    {
        Version = BigInteger.Zero;
        Subject = subject;
        SubjectPublicKeyInfo = subjectPkInfo;
        Attributes = (attributes ?? []).ToArray();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSigningRequestTemplate"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
    /// <exception cref="InvalidOperationException">Thrown if template version is other than <c>0</c></exception>
    public CertificateSigningRequestTemplate(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Version = sequenceReader.ReadInteger();
        if (Version != BigInteger.Zero)
        {
            throw new InvalidOperationException("Unsupported CSR version");
        }
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.Sequence)))
        {
            Subject = new NameTemplate(sequenceReader);
        }

        if (sequenceReader.HasData)
        {
            var tag = sequenceReader.PeekTag();
            if (sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                SubjectPublicKeyInfo = new SubjectPublicKeyInfoTemplate(sequenceReader, tag);
            }
        }

        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            var attributesReader = sequenceReader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 1));
            List<CsrAttribute> attributes = [];
            while (attributesReader.HasData)
            {
                attributes.Add(new CsrAttribute(attributesReader));
            }

            Attributes = attributes.AsReadOnly();
        }
        else
        {
            Attributes = [];
        }
    }

    /// <summary>
    /// Gets the version of the CSR.
    /// </summary>
    public BigInteger Version { get; }

    /// <summary>
    /// Gets the subject <see cref="NameTemplate"/> of the CSR.
    /// </summary>
    public NameTemplate? Subject { get; }

    /// <summary>
    /// Gets the optional subject public key info <see cref="SubjectPublicKeyInfoTemplate"/> of the CSR.
    /// </summary>
    public SubjectPublicKeyInfoTemplate? SubjectPublicKeyInfo { get; }

    /// <summary>
    /// Gets the optional CRI attribute requirements.
    /// Full X.509 extension requirements use Oids.Pkcs9ExtensionRequest and partial template requirements MAY use
    /// Oids.Pkcs9ExtensionRequestTemplate.
    /// </summary>
    public IReadOnlyList<CsrAttribute> Attributes { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence())
        {
            writer.WriteInteger(Version);
            Subject?.Encode(writer);
            SubjectPublicKeyInfo?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
            if (Attributes.Count > 0)
            {
                using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    foreach (var attribute in Attributes)
                    {
                        attribute.Encode(writer);
                    }
                }
            }
        }
    }
}
