/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

namespace OpenCertServer.Tpm2Lib;

using System.Security.Cryptography;
using System.Text;

public class ByteBuf
{
    private const int DefaultSize = 1024;
    private int _putPos;
    private int _getPos;
    private byte[] _buf;

    public ByteBuf()
    {
        _buf = new byte[DefaultSize];
        _putPos = 0;
        _getPos = 0;
    }

    public ByteBuf(int size)
    {
        _buf = new byte[size];
        _putPos = 0;
        _getPos = 0;
    }

    public ByteBuf(byte[] x)
    {
        _buf = x;
        _getPos = 0;
        _putPos = x.Length;
    }

    public ByteBuf Clone()
    {
        var newBuf = new ByteBuf(GetBuffer());
        newBuf._getPos = _getPos;
        newBuf._putPos = _putPos;
        return newBuf;
    }

    public int BytesRemaining()
    {
        return _putPos - _getPos;
    }

    public void Append(byte[] x)
    {
        if (_putPos + x.Length > _buf.Length)
        {
            // Extend the array
            var newLen = _buf.Length * 2;
            if (newLen < _putPos + x.Length)
            {
                // Big input hack
                newLen = (_putPos + x.Length) + 1024;
            }

            var buf2 = new byte[newLen];
            Array.Copy(_buf, buf2, _buf.Length);
            _buf = buf2;
        }

        Array.Copy(x, 0, _buf, _putPos, x.Length);
        _putPos += x.Length;
    }

    public byte[] GetBuffer()
    {
        var temp = new byte[_putPos];
        Array.Copy(_buf, temp, _putPos);
        return temp;
    }

    public void SetBytesInMiddle(byte[] bytesToSet, int pos)
    {
        if (pos + bytesToSet.Length > GetSize())
        {
            throw new ArgumentOutOfRangeException(nameof(pos), "Position is not in allocated buffer");
        }

        Array.Copy(bytesToSet, 0, _buf, pos, bytesToSet.Length);
    }

    public byte[] GetBytesInMiddle(int startPos, int length)
    {
        var temp = new byte[length];
        Array.Copy(_buf, startPos, temp, 0, length);
        return temp;
    }

    public byte[] RemoveBytesInMiddle(int startPos, int length)
    {
        var res = GetBytesInMiddle(startPos, length);
        // Close the gap
        for (var j = startPos; j < _putPos - length; j++)
        {
            _buf[j] = _buf[j + length];
        }

        _putPos -= length;
        return res;
    }

    public int GetSize()
    {
        return _putPos;
    }

    public int GetGetPos()
    {
        return _getPos;
    }

    public void SetGetPos(int newGetPos)
    {
        if (newGetPos < 0 || newGetPos > GetSize())
        {
            throw new Exception("SetGetPos: Invalid position");
        }

        _getPos = newGetPos;
    }

    public byte[] Extract(int num)
    {
        if (_getPos + num > _putPos)
        {
            throw new ArgumentOutOfRangeException("ByteBuf exception removing "
              + num + " bytes at position " + _getPos + " from an array of " + _putPos);
        }

        var ret = new byte[num];
        Array.Copy(_buf, _getPos, ret, 0, num);
        _getPos += num;
        return ret;
    }
}

/// <summary>
/// provide implementation of a pseudo-RNG used by all TSS.Net facilities.
/// </summary>
public class Prng
{
    public const int RandMaxBytes = 1024 * 1024;

    /// <summary>
    /// PRNG seed for this run. Can be set by SetRngSeed() or from
    /// the standard system RNG.
    /// </summary>
    private byte[]? _seed;

    /// <summary>
    /// A buffer of random data that is emptied on calls to GetRandom() and filled
    /// when the buffer is empty through FillRandBuf().
    /// </summary>
    private ByteBuf _buf = new ByteBuf();

    /// <summary>
    /// Counter for each round of buffer filling.
    /// </summary>
    private int _round;

    /// <summary>
    /// Default RNG used by the library
    /// </summary>
    private static readonly RNGCryptoServiceProvider CryptoRand = new RNGCryptoServiceProvider();

    /// <summary>
    /// Set the tester PRNG seed to random value from the system RNG
    /// </summary>
    public void SetRngRandomSeed()
    {
        lock (this)
        {
            if (_seed != null)
            {
                return;
            }

            _seed = new byte[32];
            CryptoRand.GetBytes(_seed);
            _round = 0;
            FillRandBuf();
        }
    }

    /// <summary>
    /// Retrives the requested number of pseudo-random bytes from the internal pool,
    /// and replenishes it, if necessary.
    /// </summary>
    public byte[] GetRandomBytes(int numBytes)
    {
        if (numBytes > RandMaxBytes)
        {
            throw new ArgumentException("GetRandomBytes: Too many bytes requested " + numBytes);
        }

        // Make sure that the RNG is properly seeded
        if (_seed == null)
        {
            SetRngRandomSeed();
        }

        // Fill or refill the buffer
        lock (this)
        {
            // ReSharper disable once PossibleNullReferenceException
            if (_buf.BytesRemaining() < numBytes)
            {
                FillRandBuf();
            }

            // And return the data
            return _buf.Extract(numBytes);
        }
    }

    private void FillRandBuf()
    {
        // Fill the buffer with random data
        var data = KDF.KDFa(TpmAlgId.Sha256, _seed, "RNG",
            BitConverter.GetBytes(_round),
            [], RandMaxBytes * 8);
        _round++;
        _buf = new ByteBuf(data);
    }
} // PRNG

/// <summary>
/// Provides formatting for structures and other TPM types.
/// </summary>
internal class TpmStructPrinter
{
    private StringBuilder _b;

    /// <summary>
    /// Current printing indent
    /// </summary>
    private int _indent;

    internal TpmStructPrinter()
    {
        _b = new StringBuilder();
        _indent = 0;
    }

    public override string ToString()
    {
        // Do some final formatting (change ^ for tab)
        var firstCharInLine = 0;
        var numSpacesAtStart = 0;
        var inStartSpaces = true;
        var tabNum = 0;

        for (var j = 0; j < _b.Length; j++)
        {
            if (_b[j] == '\n')
            {
                firstCharInLine = j;
                inStartSpaces = true;
                tabNum = 0;
                numSpacesAtStart = 0;
                continue;
            }

            if (inStartSpaces && _b[j] != ' ')
            {
                inStartSpaces = false;
                firstCharInLine = j;
                numSpacesAtStart++;
            }

            if (_b[j] == '^')
            {
                tabNum++;
                var tabPos = numSpacesAtStart + 0 + tabNum * 16;
                var currentColumn = j - firstCharInLine;
                var toInsert = " "; // At least one space
                if (currentColumn < tabPos)
                {
                    toInsert = new string(' ', tabPos - currentColumn);
                }

                _b = _b.Replace("^", toInsert, j, 1);
            }
        }

        return _b.ToString();
    }

    internal void PrintName(string name)
    {
        _b.AppendFormat("{0}\n", name);
        _indent++;
    }

    private void AddLine(StringBuilder b, string formatString, params string[] data)
    {
        const int firstTab = 24;
        const int secondTab = 50;
        // Coding
        //   @ - first tab
        //   # - second tab
        // We always add indent spaces

        // ReSharper disable once RedundantAssignment
        var s = formatString = Spaces() + formatString;

        // Is anything too big to fit?
        if (data[1].Length > secondTab - firstTab)
        {
            var dd = data[1];
            if (dd.Contains('|'))
            {
                // Split enum OR onto multiple lines
                dd = dd.Replace("|", "|\n" + new string(' ', firstTab + 1));
            }

            if (dd.Contains(".."))
            {
                // Split hex array
                dd = dd.Replace("..", "..\n" + new string(' ', firstTab + 2));
            }

            data[1] = dd;
        }

        // Fill it in
        // ReSharper disable once CoVariantArrayConversion
        s = string.Format(s, data);

        // Set the tabs
        var outS = "";
        var column = 0;
        foreach (var c in s)
        {
            if (c == '\n')
            {
                column = -1;
            }

            if (c == '@')
            {
                var numSpaces = firstTab - column;
                if (numSpaces <= 0)
                {
                    numSpaces = 1;
                }

                outS += new string(' ', numSpaces);
                column += numSpaces;
                continue;
            }

            if (c == '#')
            {
                var numSpaces = secondTab - column;
                if (numSpaces <= 0)
                {
                    numSpaces = 1;
                }

                outS += new string(' ', numSpaces);
                column += numSpaces;
                continue;
            }

            outS += c;
            column++;
        }

        outS += "\n";
        b.Append(outS);
    }

    internal void Print(string name, string type, object? o)
    {
        if (o == null)
        {
            // E.g. inPrivate null SomeStruct
            AddLine(_b, "{0}@{1}#{2}", name, "null", type);
            return;
        }

        // ReSharper disable once CanBeReplacedWithTryCastAndCheckForNull
        if (o is TpmStructureBase)
        {
            var ss = type;
            if (ss.StartsWith('I'))
            {
                // If the member is an interface, also print the type of entity being dumped
                var intType = o.GetType().ToString();
                intType = intType[(intType.LastIndexOf('.') + 1)..];

                type = intType;
            }

            // Print name and type but not the contents (printed recursively later)
            AddLine(_b, "{0}@-#{1}", name, type);
            // Recurse
            _indent++;
            ((TpmStructureBase)o).ToStringInternal(this);
            _indent--;
            return;
        }

        // ReSharper disable once CanBeReplacedWithTryCastAndCheckForNull
        if (o is Enum)
        {
            var en = (Enum)o;
            var s = Enum.Format(en.GetType(), en, "g");
            s = s.Replace(',', '|');
            // name   Elem1|Elem2
            AddLine(_b, "{0}@{1}#{2}", name, s, type);
            return;
        }

        if (o is ValueType)
        {
            //checked that this actually works with Int64, etc.
            var val = o is ulong ? (long)Convert.ToUInt64(o) : Convert.ToInt64(o);

            var hexString = Convert.ToString(val, 16);

            // ReSharper disable once SpecifyACultureInStringConversionExplicitly
            AddLine(_b, "{0}@{1} (0x{2})#{3}", name, o.ToString(), hexString, type);
            return;
        }

        // ReSharper disable once CanBeReplacedWithTryCastAndCheckForNull
        if (o is not Array)
        {
            throw new NotImplementedException("Print: Unknown type " + o.GetType());
        }

        var a = (Array)o;
        var elementType = o.GetType().GetElementType();
        if (elementType == typeof(byte))
        {
            // Byte arrays as special -
            var hexString = "0x" + Globs.HexFromByteArray((byte[])a, 8);
            var typeString = $"byte[{a.Length}]";
            AddLine(_b, "{0}@{1}#{2}", name, hexString, typeString);
        }
        // ReSharper disable once RedundantIfElseBlock
        else
        {
            _b.AppendFormat("{0}Array - {1}[{2}]\n", Spaces(), type, a.Length);
            _indent++;
            for (var j = 0; j < a.Length; j++)
            {
                var elem = a.GetValue(j);
                // ReSharper disable once SpecifyACultureInStringConversionExplicitly
                Print(elem.GetType().ToString(), j.ToString(), elem);
            }

            _indent--;
        }
    }

    private string Spaces()
    {
        return new string(' ', _indent * 2);
    }
}
