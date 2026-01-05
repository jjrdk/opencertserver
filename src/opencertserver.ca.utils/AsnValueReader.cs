using System.Formats.Asn1;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpenCertServer.Ca.Utils;

internal ref struct AsnValueReader
{
    private static readonly byte[] SingleByte = new byte[1];

    private ReadOnlySpan<byte> _span;
    private readonly AsnEncodingRules _ruleSet;

    internal AsnValueReader(ReadOnlySpan<byte> span, AsnEncodingRules ruleSet)
    {
        _span = span;
        _ruleSet = ruleSet;
    }

    internal bool HasData => !_span.IsEmpty;

    internal void ThrowIfNotEmpty()
    {
        if (!_span.IsEmpty)
        {
            new AsnReader(SingleByte, _ruleSet).ThrowIfNotEmpty();
        }
    }

    internal Asn1Tag PeekTag()
    {
        return Asn1Tag.Decode(_span, out _);
    }

    internal ReadOnlySpan<byte> PeekContentBytes()
    {
        AsnDecoder.ReadEncodedValue(
            _span,
            _ruleSet,
            out var contentOffset,
            out var contentLength,
            out _);

        return _span.Slice(contentOffset, contentLength);
    }

    internal ReadOnlySpan<byte> PeekEncodedValue()
    {
        AsnDecoder.ReadEncodedValue(_span, _ruleSet, out _, out _, out var consumed);
        return _span.Slice(0, consumed);
    }

    internal ReadOnlySpan<byte> ReadEncodedValue()
    {
        var value = PeekEncodedValue();
        _span = _span.Slice(value.Length);
        return value;
    }

    internal bool ReadBoolean(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadBoolean(_span, _ruleSet, out var consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    internal BigInteger ReadInteger(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadInteger(_span, _ruleSet, out var consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    internal bool TryReadInt32(out int value, Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.TryReadInt32(_span, _ruleSet, out value, out var consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    internal ReadOnlySpan<byte> ReadIntegerBytes(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadIntegerBytes(_span, _ruleSet, out var consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    internal bool TryReadPrimitiveBitString(
        out int unusedBitCount,
        out ReadOnlySpan<byte> value,
        Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.TryReadPrimitiveBitString(
            _span,
            _ruleSet,
            out unusedBitCount,
            out value,
            out var consumed,
            expectedTag);

        _span = _span.Slice(consumed);
        return ret;
    }

    internal byte[] ReadBitString(out int unusedBitCount, Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadBitString(
            _span,
            _ruleSet,
            out unusedBitCount,
            out var consumed,
            expectedTag);

        _span = _span.Slice(consumed);
        return ret;
    }

    internal TFlagsEnum ReadNamedBitListValue<TFlagsEnum>(Asn1Tag? expectedTag = default) where TFlagsEnum : Enum
    {
        var ret = AsnDecoder.ReadNamedBitListValue<TFlagsEnum>(_span, _ruleSet, out var consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    internal bool TryReadPrimitiveOctetString(
        out ReadOnlySpan<byte> value,
        Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.TryReadPrimitiveOctetString(
            _span,
            _ruleSet,
            out value,
            out var consumed,
            expectedTag);

        _span = _span.Slice(consumed);
        return ret;
    }

    internal byte[] ReadOctetString(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadOctetString(
            _span,
            _ruleSet,
            out var consumed,
            expectedTag);

        _span = _span.Slice(consumed);
        return ret;
    }

    internal string ReadObjectIdentifier(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadObjectIdentifier(_span, _ruleSet, out var consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    internal AsnValueReader ReadSequence(Asn1Tag? expectedTag = default)
    {
        AsnDecoder.ReadSequence(
            _span,
            _ruleSet,
            out var contentOffset,
            out var contentLength,
            out var bytesConsumed,
            expectedTag);

        var content = _span.Slice(contentOffset, contentLength);
        _span = _span.Slice(bytesConsumed);
        return new AsnValueReader(content, _ruleSet);
    }

    internal AsnValueReader ReadSetOf(Asn1Tag? expectedTag = default, bool skipSortOrderValidation = false)
    {
        AsnDecoder.ReadSetOf(
            _span,
            _ruleSet,
            out var contentOffset,
            out var contentLength,
            out var bytesConsumed,
            skipSortOrderValidation: skipSortOrderValidation,
            expectedTag: expectedTag);

        var content = _span.Slice(contentOffset, contentLength);
        _span = _span.Slice(bytesConsumed);
        return new AsnValueReader(content, _ruleSet);
    }

    internal DateTimeOffset ReadUtcTime(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadUtcTime(_span, _ruleSet, out var consumed, expectedTag: expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    internal DateTimeOffset ReadGeneralizedTime(Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadGeneralizedTime(_span, _ruleSet, out var consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    internal string ReadCharacterString(UniversalTagNumber encodingType, Asn1Tag? expectedTag = default)
    {
        var ret = AsnDecoder.ReadCharacterString(_span, _ruleSet, encodingType, out var consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }

    internal TEnum ReadEnumeratedValue<TEnum>(Asn1Tag? expectedTag = null) where TEnum : Enum
    {
        var ret = AsnDecoder.ReadEnumeratedValue<TEnum>(_span, _ruleSet, out var consumed, expectedTag);
        _span = _span.Slice(consumed);
        return ret;
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct AlgorithmIdentifierAsn
{
    internal string Algorithm;
    internal ReadOnlyMemory<byte>? Parameters;

    internal readonly void Encode(AsnWriter writer)
    {
        Encode(writer, Asn1Tag.Sequence);
    }

    internal readonly void Encode(AsnWriter writer, Asn1Tag tag)
    {
        writer.PushSequence(tag);

        try
        {
            writer.WriteObjectIdentifier(Algorithm);
        }
        catch (ArgumentException e)
        {
            throw new CryptographicException("Invalid DER encoding.", e);
        }

        if (Parameters.HasValue)
        {
            try
            {
                writer.WriteEncodedValue(Parameters.Value.Span);
            }
            catch (ArgumentException e)
            {
                throw new CryptographicException("Invalid DER encoding", e);
            }
        }

        writer.PopSequence(tag);
    }

    internal static AlgorithmIdentifierAsn Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
    {
        return Decode(Asn1Tag.Sequence, encoded, ruleSet);
    }

    internal static AlgorithmIdentifierAsn Decode(
        Asn1Tag expectedTag,
        ReadOnlyMemory<byte> encoded,
        AsnEncodingRules ruleSet)
    {
        try
        {
            var reader = new AsnValueReader(encoded.Span, ruleSet);

            DecodeCore(ref reader, expectedTag, encoded, out var decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }
        catch (AsnContentException e)
        {
            throw new CryptographicException("Invalid DER encoding.", e);
        }
    }

    internal static void Decode(
        ref AsnValueReader reader,
        ReadOnlyMemory<byte> rebind,
        out AlgorithmIdentifierAsn decoded)
    {
        Decode(ref reader, Asn1Tag.Sequence, rebind, out decoded);
    }

    internal static void Decode(
        ref AsnValueReader reader,
        Asn1Tag expectedTag,
        ReadOnlyMemory<byte> rebind,
        out AlgorithmIdentifierAsn decoded)
    {
        try
        {
            DecodeCore(ref reader, expectedTag, rebind, out decoded);
        }
        catch (AsnContentException e)
        {
            throw new CryptographicException("Invalid DER encoding.", e);
        }
    }

    private static void DecodeCore(
        ref AsnValueReader reader,
        Asn1Tag expectedTag,
        ReadOnlyMemory<byte> rebind,
        out AlgorithmIdentifierAsn decoded)
    {
        decoded = default;
        var sequenceReader = reader.ReadSequence(expectedTag);
        var rebindSpan = rebind.Span;
        int offset;
        ReadOnlySpan<byte> tmpSpan;

        decoded.Algorithm = sequenceReader.ReadObjectIdentifier();

        if (sequenceReader.HasData)
        {
            tmpSpan = sequenceReader.ReadEncodedValue();
            decoded.Parameters = rebindSpan.Overlaps(tmpSpan, out offset)
                ? rebind.Slice(offset, tmpSpan.Length)
                : tmpSpan.ToArray();
        }


        sequenceReader.ThrowIfNotEmpty();
    }
}
