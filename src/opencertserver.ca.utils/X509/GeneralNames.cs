using System.Collections.Immutable;
using System.Formats.Asn1;

namespace OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the GeneralNames class.
/// </summary>
/// <remarks>GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName</remarks>
public class GeneralNames : AsnValue
{
    public GeneralNames(params Span<GeneralName> names)
    {
        Names = [..names];
    }

    public GeneralNames(ReadOnlyMemory<byte> encoded)
        : this(new AsnReader(encoded.ToArray(), AsnEncodingRules.DER))
    {
    }

    public GeneralNames(AsnReader reader)
    {
        var tag = reader.PeekTag();
        var seq = reader.ReadSequence(tag);
        var names = new List<GeneralName>();
        while (seq.HasData)
        {
            names.Add(new GeneralName(seq));
        }

        Names = [..names];
    }

    public ImmutableArray<GeneralName> Names { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        if (Names.Length == 0)
        {
            return;
        }

        using (writer.PushSequence(tag))
        {
            foreach (var name in Names)
            {
                name.Encode(writer, null);
            }
        }
    }
}
