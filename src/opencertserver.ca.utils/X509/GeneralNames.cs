namespace OpenCertServer.Ca.Utils.X509;

using System.Collections.Immutable;
using System.Formats.Asn1;

/// <summary>
/// Defines the GeneralNames class.
/// </summary>
/// <code>
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName</code>
public class GeneralNames : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="GeneralNames"/> class.
    /// </summary>
    /// <param name="names">The sequence of names</param>
    public GeneralNames(params Span<GeneralName> names)
    {
        Names = [..names];
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GeneralNames"/> class.
    /// </summary>
    /// <param name="encoded">The raw DER encoded data.</param>
    public GeneralNames(ReadOnlyMemory<byte> encoded)
        : this(new AsnReader(encoded.ToArray(), AsnEncodingRules.DER))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GeneralNames"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
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

    /// <summary>
    /// Gets the sequence of names.
    /// </summary>
    public ImmutableArray<GeneralName> Names { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
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
