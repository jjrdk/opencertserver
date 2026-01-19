using System.Formats.Asn1;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.X509Extensions.Templates;

public class SubjectPublicKeyInfoTemplate : AsnValue
{
    public SubjectPublicKeyInfoTemplate(Oid algorithm, byte[]? publicKey = null)
    {
        Algorithm = algorithm;
        PublicKey = publicKey;
    }

    public Oid Algorithm { get; }
    public byte[]? PublicKey { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(Algorithm.Value!);
            if (PublicKey != null)
            {
                writer.WriteBitString(PublicKey.AsSpan());
            }
        }
    }
}
