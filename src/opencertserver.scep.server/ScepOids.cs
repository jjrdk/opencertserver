namespace OpenCertServer.Scep.Server;

/// <summary>
/// Object identifiers of the SCEP message attributes (RFC 8894, section 3.2.1).
/// </summary>
public static class ScepOids
{
    /// <summary>The <c>messageType</c> attribute (PrintableString).</summary>
    public const string MessageType = "2.16.840.1.113733.1.9.2";

    /// <summary>The <c>pkiStatus</c> attribute (PrintableString).</summary>
    public const string PkiStatus = "2.16.840.1.113733.1.9.3";

    /// <summary>The <c>failInfo</c> attribute (PrintableString).</summary>
    public const string FailInfo = "2.16.840.1.113733.1.9.4";

    /// <summary>The <c>senderNonce</c> attribute (OCTET STRING).</summary>
    public const string SenderNonce = "2.16.840.1.113733.1.9.5";

    /// <summary>The <c>recipientNonce</c> attribute (OCTET STRING).</summary>
    public const string RecipientNonce = "2.16.840.1.113733.1.9.6";

    /// <summary>The <c>transactionID</c> attribute (PrintableString).</summary>
    public const string TransactionId = "2.16.840.1.113733.1.9.7";

    /// <summary>The PKCS#9 <c>challengePassword</c> attribute of a PKCS#10 request.</summary>
    public const string ChallengePassword = "1.2.840.113549.1.9.7";

    /// <summary>The CMS <c>data</c> content type.</summary>
    public const string Data = "1.2.840.113549.1.7.1";
}

/// <summary>
/// SCEP message types (RFC 8894, section 3.2.1.2), as carried in the <c>messageType</c> attribute.
/// </summary>
public enum ScepMessageType
{
    /// <summary>Response to a request.</summary>
    CertRep = 3,

    /// <summary>Renewal of an existing certificate.</summary>
    RenewalReq = 17,

    /// <summary>Initial enrollment.</summary>
    PkcsReq = 19,

    /// <summary>Poll for a pending request.</summary>
    CertPoll = 20,

    /// <summary>Retrieve a certificate.</summary>
    GetCert = 21,

    /// <summary>Retrieve a CRL.</summary>
    GetCrl = 22
}

/// <summary>
/// The <c>failInfo</c> values of a failed <c>CertRep</c> (RFC 8894, section 3.2.1.4).
/// </summary>
public enum ScepFailInfo
{
    /// <summary>Unrecognized or unsupported algorithm.</summary>
    BadAlg = 0,

    /// <summary>Integrity check (signature verification) failed.</summary>
    BadMessageCheck = 1,

    /// <summary>Transaction not permitted or supported.</summary>
    BadRequest = 2,

    /// <summary>The signingTime attribute was not sufficiently close to the system time.</summary>
    BadTime = 3,

    /// <summary>No certificate could be identified matching the provided criteria.</summary>
    BadCertId = 4
}
