namespace OpenCertServer.Est.Server.Handlers;

using System.Net;
using OpenCertServer.Ca.Utils.X509.Templates;

/// <summary>
/// Represents the EST /csrattrs response selected by the server.
/// </summary>
public sealed class CsrAttributesResponse
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CsrAttributesResponse"/> class.
    /// </summary>
    private CsrAttributesResponse(HttpStatusCode statusCode, CsrAttributes? attributes = null)
    {
        StatusCode = statusCode;
        Attributes = attributes;
    }

    /// <summary>
    /// Gets the HTTP status code to emit.
    /// </summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>
    /// Gets the CSR attributes payload when the response is successful.
    /// </summary>
    public CsrAttributes? Attributes { get; }

    /// <summary>
    /// Creates a successful CSR attributes response.
    /// </summary>
    public static CsrAttributesResponse Available(CsrAttributes attributes)
    {
        return new CsrAttributesResponse(HttpStatusCode.OK, attributes);
    }

    /// <summary>
    /// Creates a successful RFC 9908 template-based CSR attributes response.
    /// </summary>
    public static CsrAttributesResponse FromTemplate(CertificateSigningRequestTemplate template)
    {
        return Available(new CsrAttributes(templates: [template]));
    }

    /// <summary>
    /// Creates an unavailable CSR attributes response.
    /// </summary>
    public static CsrAttributesResponse Unavailable(HttpStatusCode statusCode = HttpStatusCode.NoContent)
    {
        return new CsrAttributesResponse(statusCode);
    }
}

