/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System.Diagnostics;
using System.Reflection;

namespace OpenCertServer.Tpm2Lib;

public enum DataRepresentation
{
    Tpm,
    LittleEndian
}

/// <summary>
/// Support for marshaling of TPM structures and other types to and from the TPM.
/// </summary>
public class Marshaller
{
    DataRepresentation Repr;

    ByteBuf Buffer;

    // We use length-prepended structures in command marshaling and some other places.
    Stack<SizePlaceholder> SizesToFillIn;

    string[] QualifiedName;
    int QualNamePos;
    int ElementStart;
    int ElementEnd;

    public List<int> SizedStructLen = new List<int>();

    public Marshaller(DataRepresentation mt = DataRepresentation.Tpm)
    {
        Reset(mt);
    }

    public Marshaller(byte[] buf, DataRepresentation mt = DataRepresentation.Tpm)
    {
        Reset(mt);
        Buffer = new ByteBuf(buf);
    }

    public void Reset(DataRepresentation mt = DataRepresentation.Tpm)
    {
        Buffer = new ByteBuf();
        SizesToFillIn = new Stack<SizePlaceholder>();
        Repr = mt;
    }

    public static byte[] GetTpmRepresentation(params object[] theObjects)
    {
        var m = new Marshaller();
        foreach(var o in theObjects)
        {
            m.Put(o, null);
        }
        return m.GetBytes();
    }

    /// <summary>
    /// Convert to a USHORT length-prepended byte array.
    /// </summary>
    /// <param name="x"></param>
    /// <returns></returns>
    public static byte[] ToTpm2B(byte[] x)
    {
        return GetTpmRepresentation((ushort)x.Length, x);
    }

    /// <summary>
    /// Assuming a ushort-prepended array, return the payload (if properly formed).
    /// </summary>
    /// <param name="x"></param>
    /// <returns></returns>
    static public byte[] Tpm2BToBuffer(byte[] x)
    {
        var m = new Marshaller(x);
        var len = m.Get<ushort>();
        if (len != x.Length - 2)
        {
            throw new ArgumentException("Tpm2BToBuffer: Ill formed TPM2B");
        }
        var ret = new byte[len];
        Array.Copy(x, 2, ret, 0, len);
        return ret;
    }

    public byte[] GetBytes()
    {
        if (SizesToFillIn.Count != 0)
        {
            throw new Exception("Unresolved PushSize()");
        }
        var numBytes = Buffer.GetSize();
        var temp = new byte[numBytes];
        Array.Copy(Buffer.GetBuffer(), temp, numBytes);
        return temp;
    }

    public uint GetGetPos()
    {
        return (uint)Buffer.GetGetPos();
    }

    public byte[] RemoveBytesInMiddle(int pos, int len)
    {
        return Buffer.RemoveBytesInMiddle(pos, len);
    }

    public uint GetPutPos()
    {
        return (uint)Buffer.GetSize();
    }

    public void SetGetPos(uint getPos)
    {
        Buffer.SetGetPos((int)getPos);
    }

    public static T FromTpmRepresentation<T>(byte[] b)
    {
        var m = new Marshaller(b);
        object obj = m.Get<T>();
        return (T)obj;
    }

    private object FromNetValueType(Type tp)
    {
        var data = Buffer.Extract(Globs.SizeOf(tp));
        if (data == null)
        {
            return null;
        }

        if (Repr == DataRepresentation.Tpm)
        {
            return Globs.NetToHostValue(tp, data);
        }
        if (Repr == DataRepresentation.LittleEndian)
        {
            return Globs.FromBytes(tp, data);
        }
        // Unsupported type
        Debug.Assert(false);
        return null;
    }

    public void Put(object o, string name)
    {
        PutInternal(o, name);
    }

    /// <summary>
    /// Gets the location start and length of an embedded element in a TPM structure in TPM-canonical form.
    /// </summary>
    /// <param name="o"></param>
    /// <param name="qualifiedName"></param>
    /// <param name="start"></param>
    /// <param name="finish"></param>
    public static void GetFragmentInfo(object o, string qualifiedName, out int start, out int finish)
    {
        var m = new Marshaller {QualifiedName = qualifiedName.Split(new[] {'.'}), QualNamePos = 0};
        m.PutInternal(o, "");
        start = m.ElementStart;
        finish = m.ElementEnd;
        m.QualifiedName = null;
    }

    public void PutInternal(object o, string name)
    {
        var measuringElement = false;
        if (QualifiedName != null)
        {
            // We are searching for the start and length of a fragment
            if (name == QualifiedName[QualNamePos])
            {
                ElementStart = (int)GetPutPos();
                measuringElement = true;
            }
        }

        if (o == null)
        {
        }
        // ReSharper disable once CanBeReplacedWithTryCastAndCheckForNull
        else if (o is TpmStructureBase)
        {
            ((TpmStructureBase)o).ToNet(this);
        }
        else if (o is Enum)
        {
            var underlyingType = Enum.GetUnderlyingType(o.GetType());
            if (underlyingType == typeof(byte))
            {
                // ReSharper disable once SuggestUseVarKeywordEvident
                // ReSharper disable once PossibleInvalidCastException
                var x = (byte)o;
                ToNetValueType(x, name);
            }
            else if (underlyingType == typeof(ushort))
            {
                // ReSharper disable once SuggestUseVarKeywordEvident
                // ReSharper disable once PossibleInvalidCastException
                var x = (ushort)o;
                ToNetValueType(x, name);
            }
            else if (underlyingType == typeof(uint))
            {
                // ReSharper disable once SuggestUseVarKeywordEvident
                // ReSharper disable once PossibleInvalidCastException
                var x = (uint)o;
                ToNetValueType(x, name);
            }
            else if (underlyingType == typeof(sbyte))
            {
                // ReSharper disable once SuggestUseVarKeywordEvident
                // ReSharper disable once PossibleInvalidCastException
                var x = (byte)((sbyte)o);
                ToNetValueType(x, name);
            }
            else if (underlyingType == typeof(ulong))
            {
                // ReSharper disable once SuggestUseVarKeywordEvident
                // ReSharper disable once PossibleInvalidCastException
                var x = (ulong)o;
                ToNetValueType(x, name);
            }
            else
            {
                throw new ArgumentException("PutInternal: Unsupported enum type");
            }
        }
        else if (o is ValueType)
        {
            ToNetValueType(o, name);
        }
        // ReSharper disable once CanBeReplacedWithTryCastAndCheckForNull
        else if (o is Array)
        {
            var a = (Array)o;
            var count = 0;
            foreach (var elem in a)
            {
                Put(elem, name + count);
                count++;
            }
        }
        else
        {
            throw new NotImplementedException("PutInternal: Unsupported object type");
        }

        if (measuringElement)
        {
            ElementEnd = (int)GetPutPos();
        }
    }

    public void PutUintPrependedArray(byte[] x, string name)
    {
        var l = (uint)x.Length;
        Put(l, name + "_length");
        Put(x, name);
    }

    public object Get(Type tp, string name)
    {
        if (typeof(TpmStructureBase).GetTypeInfo().IsAssignableFrom(tp.GetTypeInfo()))
        {
            var o = Activator.CreateInstance(tp);
            ((TpmStructureBase)o).ToHost(this);
            return o;
        }
        if (typeof(Enum).GetTypeInfo().IsAssignableFrom(tp.GetTypeInfo()))
        {
            var underlyingType = Enum.GetUnderlyingType(tp);
            var o = FromNetValueType(underlyingType);
            return o == null ? null : Enum.ToObject(tp, o);
        }

        if (typeof(ValueType).GetTypeInfo().IsAssignableFrom(tp.GetTypeInfo()))
        {
            var o = FromNetValueType(tp);
            return o;
        }
        throw new NotImplementedException("Get: Not supported type " + tp);
    }

    public T Get<T>()
    {
        var tempO = Get(typeof(T), "");
        return (T)tempO;
    }

    public void PutSizeTag(int size, int sizeLength, string name)
    {
        var s = BitConverter.GetBytes(size);
        if (sizeLength != sizeof(uint))
        {
            Array.Resize(ref s, sizeLength);
        }
        PutInternal(Globs.ReverseByteOrder(s), name);
    }

    public int GetSizeTag(int sizeLength, string name)
    {
        var counterData = GetArray<byte>(sizeLength, name);
        if (Repr == DataRepresentation.Tpm)
        {
            counterData = Globs.ReverseByteOrder(counterData);
        }
        Array.Resize(ref counterData, sizeof(int));
        return BitConverter.ToInt32(counterData, 0);
    }

    public T[] GetArray<T>(int length, string name = "")
    {
        return GetArray(typeof(T), length, name) as T[];
    }

    public object GetArray(Type elementType, int length, string name = "")
    {
        var a = Array.CreateInstance(elementType, length);
        for (var j = 0; j < length; j++)
        {
            var val = Get(elementType, name + j);
            a.SetValue(val, j);
        }
        return a;
    }

    public byte[] GetNBytes(int n)
    {
        return Buffer.Extract(n);
    }

    void ToNetValueType(object o, string name)
    {
        if (Repr == DataRepresentation.Tpm)
        {
            Buffer.Append(Globs.HostToNet(o));
            return;
        }
        if (Repr == DataRepresentation.LittleEndian)
        {
            Buffer.Append(Globs.GetBytes(o));
        }
        throw new Exception("ToNetValueType: Unsupported marshaling type " + Repr);
    }

    public void PushLength(int numBytes)
    {
        var sp = new SizePlaceholder(Buffer.GetSize(), numBytes);
        SizesToFillIn.Push(sp);
        switch (numBytes)
        {
            case 1:
                ToNet((byte)0xFF);
                return;
            case 2:
                ToNet((ushort)0xFFFF);
                return;
            // ReSharper disable once RedundantCast
            case 4:
                ToNet((uint)0xFFFFFFFF);
                return;
            case 8:
                ToNet((ulong)0xFFFFFFFFFFFFFFFF);
                return;
            default:
                throw new ArgumentException("PushLength: Invalid length " + numBytes);
        }
    }

    void PopAndSetLengthImpl(SizePlaceholder sp, int len)
    {
        switch (sp.Length)
        {
            case 1:
                Buffer.SetBytesInMiddle(Globs.HostToNet((byte)len), sp.StartPos);
                return;
            case 2:
                Buffer.SetBytesInMiddle(Globs.HostToNet((ushort)len), sp.StartPos);
                return;
            case 4:
                Buffer.SetBytesInMiddle(Globs.HostToNet((uint)len), sp.StartPos);
                return;
            case 8:
                Buffer.SetBytesInMiddle(Globs.HostToNet((ulong)len), sp.StartPos);
                return;
            default:
                throw new ArgumentException("PopAndSetLengthImpl: Invalid length " + sp.Length);
        }
    }
    public void PopAndSetLength()
    {
        var sp = SizesToFillIn.Pop();
        var len = Buffer.GetSize() - sp.StartPos - sp.Length;
        PopAndSetLengthImpl(sp, len);
    }

    public void PopAndSetLengthToTotalLength()
    {
        PopAndSetLengthImpl(SizesToFillIn.Pop(), Buffer.GetSize());
    }

    void ToNet(object o)
    {
        Put(o, null);
    }
} // class Marshaller

internal struct SizePlaceholder
{
    internal SizePlaceholder(int startPos, int length)
    {
        StartPos = startPos;
        Length = length;
    }
    internal int StartPos;
    internal int Length;
}