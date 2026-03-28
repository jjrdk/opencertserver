namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines an OCSP request
/// </summary>
/// <code>
/// SEQUENCE {
///     reqCert                     CertID,
///     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL
/// }
/// </code>
public class Request : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Request"/> class.
    /// </summary>
    public Request(CertId certId, X509ExtensionCollection? singleRequestExtensions = null)
    {
        CertIdentifier = certId;
        SingleRequestExtensions = singleRequestExtensions;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Request"/> class.
    /// </summary>
    public Request(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        CertIdentifier = new CertId(sequenceReader);
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            var extReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            SingleRequestExtensions = new X509ExtensionCollection();
            while (extReader.HasData)
            {
                var ext = extReader.DecodeExtension();
                SingleRequestExtensions.Add(ext);
            }

            extReader.ThrowIfNotEmpty();
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    /// <summary>
    /// Gets the certificate identifier requested for status checking.
    /// </summary>
    public CertId CertIdentifier { get; }

    /// <summary>
    /// Gets the optional per-request extensions.
    /// </summary>
    public X509ExtensionCollection? SingleRequestExtensions { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        CertIdentifier.Encode(writer);
        if (SingleRequestExtensions != null)
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                foreach (var ext in SingleRequestExtensions)
                {
                    ext.Encode(writer);
                }
            }
        }

        writer.PopSequence(tag);
    }
}
