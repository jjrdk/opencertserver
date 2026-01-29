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
    public CertificateSigningRequestTemplate(
        NameTemplate? subject = null,
        SubjectPublicKeyInfoTemplate? subjectPkInfo = null)
    {
        // TODO: Support CRIAttributes
        Version = BigInteger.Zero;
        Subject = subject;
        SubjectPublicKeyInfo = subjectPkInfo;
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

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence())
        {
            writer.WriteInteger(Version);
            Subject?.Encode(writer);
            SubjectPublicKeyInfo?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
        }
    }
}
