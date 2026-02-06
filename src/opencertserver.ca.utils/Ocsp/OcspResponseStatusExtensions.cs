using System.Formats.Asn1;

namespace OpenCertServer.Ca.Utils.Ocsp;

public static class OcspResponseStatusExtensions
{
    public static string GetDescription(this OcspResponseStatus status)
    {
        return status switch
        {
            OcspResponseStatus.Successful => "The OCSP response has valid confirmations.",
            OcspResponseStatus.MalformedRequest => "Illegal confirmation request.",
            OcspResponseStatus.InternalError => "Internal error in issuer.",
            OcspResponseStatus.TryLater => "Try again later.",
            OcspResponseStatus.SigRequired => "Must sign the request.",
            OcspResponseStatus.Unauthorized => "Request unauthorized.",
            _ => "Unknown status."
        };
    }

    public static OcspBasicResponse GetBasicResponse(this ResponseBytes response)
    {
        if (response.ResponseType.Value != "")
        {
            throw new InvalidOperationException("Unsupported OCSP response type");
        }
        var reader = new AsnReader(response.Response, AsnEncodingRules.DER);
        return new OcspBasicResponse(reader);
    }
}