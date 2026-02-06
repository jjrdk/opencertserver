using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

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
    public Request(CertId certId, X509ExtensionCollection? singleRequestExtensions = null)
    {
        CertIdentifier = certId;
        SingleRequestExtensions = singleRequestExtensions;
    }

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

    public CertId CertIdentifier { get; }

    public X509ExtensionCollection? SingleRequestExtensions { get; }

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
