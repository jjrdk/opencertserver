namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using X509;

/// <summary>
/// Defines a TBSRequest
/// </summary>
/// <code>
/// SEQUENCE {
///     version             [0]     EXPLICIT Version DEFAULT v1,
///     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
///     requestList                 SEQUENCE OF Request,
///     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL
/// }
/// </code>
public class TbsRequest : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TbsRequest"/> class.
    /// </summary>
    public TbsRequest(
        TypeVersion version = TypeVersion.V1,
        GeneralName? requestorName = null,
        IList<Request>? requestList = null,
        X509ExtensionCollection? requestExtensions = null)
    {
        Version = version;
        RequestorName = requestorName;
        RequestList = requestList ?? [];
        RequestExtensions = requestExtensions;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TbsRequest"/> class.
    /// </summary>
    public TbsRequest(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        while (sequenceReader.HasData)
        {
            var tag = sequenceReader.PeekTag();
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                // version [0] EXPLICIT Version DEFAULT v1
                var versionReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                Version = (TypeVersion)(int)versionReader.ReadInteger();
                versionReader.ThrowIfNotEmpty();
            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            {
                var encodedValue = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
                RequestorName = new GeneralName(encodedValue);
            }
            else if (tag.HasSameClassAndValue(Asn1Tag.Sequence))
            {
                var listReader = sequenceReader.ReadSequence();
                var requests = new List<Request>();
                while (listReader.HasData)
                {
                    requests.Add(new Request(listReader));
                }

                RequestList = requests;
            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                // requestExtensions [2] EXPLICIT Extensions
                var explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                var extReader = explicitReader.ReadSequence();
                explicitReader.ThrowIfNotEmpty();
                RequestExtensions = [];
                while (extReader.HasData)
                {
                    var ext = extReader.DecodeExtension();
                    RequestExtensions.Add(ext);
                }

                extReader.ThrowIfNotEmpty();
            }
        }

        RequestList ??= [];
    }

    /// <summary>
    /// Gets the OCSP request version.
    /// </summary>
    public TypeVersion Version { get; }

    /// <summary>
    /// Gets the optional requestor name.
    /// </summary>
    public GeneralName? RequestorName { get; }

    /// <summary>
    /// Gets the list of certificate status requests.
    /// </summary>
    public IList<Request> RequestList { get; }

    /// <summary>
    /// Gets the optional request extensions.
    /// </summary>
    public X509ExtensionCollection? RequestExtensions { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        if (Version != TypeVersion.V1)
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                writer.WriteInteger((int)Version);
            }
        }

        if (RequestorName != null)
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            {
                RequestorName?.Encode(writer);
            }
        }

        if (RequestList.Count > 0)
        {
            writer.PushSequence();
            foreach (var request in RequestList)
            {
                request.Encode(writer);
            }

            writer.PopSequence();
        }

        if (RequestExtensions != null)
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)))
            using (writer.PushSequence())
            {
                foreach (var ext in RequestExtensions)
                {
                    ext.Encode(writer);
                }
            }
        }

        writer.PopSequence(tag);
    }

    /// <summary>
    /// Executes the Sign operation.
    /// </summary>
    public Signature Sign(AsymmetricAlgorithm key)
    {
        var signatureGenerator = key switch
        {
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pss),
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            _ => throw new InvalidOperationException("Unsupported signing algorithm")
        };
        var writer = new AsnWriter(AsnEncodingRules.DER);
        Encode(writer);
        var dataToSign = writer.Encode();
        var signature = signatureGenerator.SignData(dataToSign, HashAlgorithmName.SHA256);
        var algorithmIdentifier = key switch
        {
            RSA => new AlgorithmIdentifier(Oids.RsaPkcs1Sha256.InitializeOid(Oids.RsaPkcs1Sha256FriendlyName)),
            ECDsa => new AlgorithmIdentifier(Oids.ECDsaWithSha256.InitializeOid(Oids.ECDsaWithSha256FriendlyName)),
            _ => throw new InvalidOperationException("Unsupported signing algorithm")
        };
        return new Signature(algorithmIdentifier, signature);
    }
}
