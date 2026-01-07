using System.Formats.Asn1;
using System.Security.Cryptography;

namespace OpenCertServer.Ca.Utils;

public record AuthorityInfoAccessExtension : CrlExtension
{
    private AuthorityInfoAccessExtension(
        Oid oid,
        bool isCritical,
        IReadOnlyCollection<AccessDescription> AccessDescriptions) : base(oid, isCritical)
    {
        this.AccessDescriptions = AccessDescriptions;
    }

    public IReadOnlyCollection<AccessDescription> AccessDescriptions { get; init; }

    public static AuthorityInfoAccessExtension Create(
        string oid,
        bool isCritical,
        ReadOnlyMemory<byte> value)
    {
        var accessDescriptions = new List<AccessDescription>();
        var accessDescriptionsReader = new AsnReader(value, AsnEncodingRules.DER);
        while (accessDescriptionsReader.HasData)
        {
            var sequenceReader = accessDescriptionsReader.ReadSequence();
            var accessMethodOid = sequenceReader.ReadObjectIdentifier();
            // For simplicity, we will not parse the GeneralName in detail here.
            var valueTag  = sequenceReader.PeekTag(); // Placeholder for actual GeneralName parsing.
            GeneralName accessLocation = new GeneralName(0, "");
            accessDescriptions.Add(new AccessDescription(new Oid(accessMethodOid), accessLocation));
            sequenceReader.ThrowIfNotEmpty();
        }
        return new AuthorityInfoAccessExtension(oid, isCritical, accessDescriptions);
    }
}
