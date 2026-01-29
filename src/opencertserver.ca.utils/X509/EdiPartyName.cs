namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;

/// <summary>
/// Defines the EdiPartyName class.
/// </summary>
/// <code>
/// EDIPartyName ::= SEQUENCE {
///  nameAssigner		[0]	DirectoryString {ub-name} OPTIONAL,
///  partyName		[1]	DirectoryString {ub-name} }
/// </code>
public class EdiPartyName : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EdiPartyName"/> class.
    /// </summary>
    /// <param name="partyName">The party name.</param>
    /// <param name="nameAssigner">The name assigner.</param>
    public EdiPartyName(DirectoryString partyName, DirectoryString? nameAssigner = null)
    {
        PartyName = partyName;
        NameAssigner = nameAssigner;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EdiPartyName"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
    /// <exception cref="ArgumentException">Thrown if initial tag is content specific.</exception>
    public EdiPartyName(AsnReader reader)
    {
        var tag = reader.PeekTag();
        if (tag.TagClass != TagClass.ContextSpecific)
        {
            throw new ArgumentException("Invalid EdiPartyName encoding", nameof(reader));
        }

        var seq = reader.ReadSequence(tag);
        while (seq.HasData)
        {
            tag = seq.PeekTag();
            switch (tag.TagValue)
            {
                case 0:
                    var nameAssignerSeq = seq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                    NameAssigner = new DirectoryString(nameAssignerSeq.ReadEncodedValue());
                    break;
                case 1:
                    var partyNameSeq = seq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                    PartyName = new DirectoryString(partyNameSeq.ReadEncodedValue());
                    break;
                default:
                    throw new ArgumentException("Invalid EdiPartyName tag", nameof(reader));
            }
        }

        if (PartyName == null)
        {
            throw new ArgumentException("EdiPartyName must contain partyName", nameof(reader));
        }
    }

    /// <summary>
    /// Gets the party name.
    /// </summary>
    public DirectoryString PartyName { get; }

    /// <summary>
    /// Gets the optional name assigner.
    /// </summary>
    public DirectoryString? NameAssigner { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag)
    {
        using (writer.PushSequence(tag))
        {
            if (NameAssigner != null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    NameAssigner.Encode(writer);
                }
            }

            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                PartyName.Encode(writer);
            }
        }
    }
}
