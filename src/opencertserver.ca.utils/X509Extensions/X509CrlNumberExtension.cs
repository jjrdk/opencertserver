using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils.X509Extensions;

public class X509CrlNumberExtension : X509Extension
{
    public X509CrlNumberExtension(ReadOnlySpan<byte> crlNumber, bool isCritical)
        : base(new Oid("2.5.29.20", "CRL Number"), crlNumber, isCritical)
    {
    }

    public X509CrlNumberExtension(BigInteger crlNumber, bool isCritical)
        : this(crlNumber.ToByteArray(), isCritical)
    {
    }

    public BigInteger CrlNumber
    {
        get { return new BigInteger(RawData); }
    }
}

/*
 * public class CrlDistPoint
           : Asn1Encodable
       {
           public static CrlDistPoint GetInstance(Asn1TaggedObject obj, bool explicitly) =>
               new CrlDistPoint(Asn1Sequence.GetInstance(obj, explicitly));

           public static CrlDistPoint GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
               new CrlDistPoint(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

           public static CrlDistPoint FromExtensions(X509Extensions extensions)
           {
               return GetInstance(
                   X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.CrlDistributionPoints));
           }

           private readonly Asn1Sequence m_seq;

           private CrlDistPoint(Asn1Sequence seq)
           {
               m_seq = seq;
           }

   		public CrlDistPoint(DistributionPoint[] points)
           {
   			m_seq = new DerSequence(points);
           }

           /**
            * Return the distribution points making up the sequence.
            *
            * @return DistributionPoint[]
            * /
           public DistributionPoint[] GetDistributionPoints() => m_seq.MapElements(DistributionPoint.GetInstance);

           /**
            * Produce an object suitable for an Asn1OutputStream.
            * <pre>
            * CrlDistPoint ::= Sequence SIZE {1..MAX} OF DistributionPoint
            * </pre>
            * /
           public override Asn1Object ToAsn1Object() => m_seq;

   		public override string ToString()
   		{
   			StringBuilder buf = new StringBuilder();
   			buf.AppendLine("CRLDistPoint:");
               foreach (DistributionPoint dp in GetDistributionPoints())
   			{
   				buf.Append("    ")
   				   .Append(dp)
                      .AppendLine();
   			}
   			return buf.ToString();
   		}
   	}
*/
