namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;

/// <summary>
/// Provides helper extensions for OCSP response status values and response payload parsing.
/// </summary>
public static class OcspResponseStatusExtensions
{
    /// <summary>
    /// Gets the description for the OCSP response status.
    /// </summary>
    /// <param name="status">The OCSP response status.</param>
    /// <returns>A string describing the status.</returns>
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

    /// <summary>
    /// Gets the basic response from the response bytes.
    /// </summary>
    /// <param name="response">The response bytes.</param>
    /// <returns>An <see cref="OcspBasicResponse"/> instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the response type is not supported.</exception>
    public static OcspBasicResponse GetBasicResponse(this ResponseBytes response)
    {
        if (response.ResponseType.Value != Oids.OcspBasicResponse)
        {
            throw new InvalidOperationException("Unsupported OCSP response type");
        }
        var reader = new AsnReader(response.Response, AsnEncodingRules.DER);
        return new OcspBasicResponse(reader);
    }
}
