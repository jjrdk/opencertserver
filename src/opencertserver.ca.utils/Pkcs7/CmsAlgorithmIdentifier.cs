using System.Formats.Asn1;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Pkcs7;

/// <summary>
/// RFC 5652 AlgorithmIdentifier for CMS key/content encryption.
/// </summary>
public sealed class CmsAlgorithmIdentifier : IAsnValue
{
    public CmsAlgorithmIdentifier(Oid algorithmOid, byte[]? encodedParameters = null)
    {
        AlgorithmOid = algorithmOid;
        EncodedParameters = encodedParameters?.ToArray();
    }

    public CmsAlgorithmIdentifier(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        AlgorithmOid = sequenceReader.ReadObjectIdentifier().InitializeOid();
        if (sequenceReader.HasData)
        {
            EncodedParameters = sequenceReader.ReadEncodedValue().ToArray();
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    public Oid AlgorithmOid { get; }

    public byte[]? EncodedParameters { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(AlgorithmOid.Value!);
            if (EncodedParameters != null)
            {
                writer.WriteEncodedValue(EncodedParameters);
            }
        }
    }
}