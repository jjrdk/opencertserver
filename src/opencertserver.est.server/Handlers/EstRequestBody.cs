namespace OpenCertServer.Est.Server.Handlers;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Formats.Asn1;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils;

/// <summary>
/// Decodes the PKCS#10 body of an EST enrollment request.
/// </summary>
/// <remarks>
/// RFC 8951 §3.1 asks receivers to tolerate whitespace (CR, LF, space, tab) in base64 content, so whitespace is
/// removed rather than rewritten. A PEM-armoured CSR is accepted as well. Base64url input remains accepted for
/// compatibility with existing clients; it cannot be confused with PEM because PEM is detected first.
/// </remarks>
internal static class EstRequestBody
{
    public static bool TryLoadCsr(
        string body,
        HttpContext context,
        CertificateRequestLoadOptions options,
        out byte[] csrDer,
        out CertificateRequest csr)
    {
        try
        {
            csrDer = DecodeCsr(body);
            csr = CertificateRequest.LoadSigningRequest(csrDer, HashAlgorithmName.SHA256, options,
                RSASignaturePadding.Pss);
            if ((options & CertificateRequestLoadOptions.SkipSignatureValidation) != 0)
            {
                using var requestedKey = csr.PublicKey.Oid.Value switch
                {
                    Oids.Rsa => (AsymmetricAlgorithm?)csr.PublicKey.GetRSAPublicKey(),
                    Oids.EcPublicKey => csr.PublicKey.GetECDsaPublicKey(),
                    _ => throw new NotSupportedException("The requested key algorithm is not supported.")
                };
                if (requestedKey == null)
                {
                    throw new CryptographicException("The requested public key could not be read.");
                }
            }
            foreach (var extension in csr.CertificateExtensions)
            {
                switch (extension.Oid?.Value)
                {
                    case "2.5.29.15":
                        _ = new X509KeyUsageExtension(extension, extension.Critical).KeyUsages;
                        break;
                    case "2.5.29.37":
                        _ = new X509EnhancedKeyUsageExtension(extension, extension.Critical).EnhancedKeyUsages;
                        break;
                    case "2.5.29.19":
                        _ = new X509BasicConstraintsExtension(extension, extension.Critical).CertificateAuthority;
                        break;
                    case "2.5.29.17":
                        var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
                        var names = reader.ReadSequence();
                        reader.ThrowIfNotEmpty();
                        while (names.HasData)
                        {
                            var tag = names.PeekTag();
                            if (tag.TagClass != TagClass.ContextSpecific || tag.TagValue > 8)
                            {
                                throw new AsnContentException();
                            }

                            switch (tag.TagValue)
                            {
                                case 1 or 2 or 6:
                                    names.ReadCharacterString(UniversalTagNumber.IA5String, tag);
                                    break;
                                case 7:
                                    names.ReadOctetString(tag);
                                    break;
                                case 8:
                                    names.ReadObjectIdentifier(tag);
                                    break;
                                default:
                                    names.ReadEncodedValue();
                                    break;
                            }
                        }
                        break;
                }
            }

            return true;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or NotSupportedException
                                   or AsnContentException or ArgumentException)
        {
            context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("OpenCertServer.Est.Server")
                .LogWarning("Rejected an invalid EST CSR ({ExceptionType})", ex.GetType().Name);
            csrDer = [];
            csr = null!;
            return false;
        }
    }

    public static IResult InvalidCsr() =>
        Results.Text("The CSR could not be read.", Constants.TextPlainMimeType, Encoding.UTF8,
            StatusCodes.Status400BadRequest);

    public static IResult InternalError(HttpContext context, Exception exception)
    {
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("OpenCertServer.Est.Server")
            .LogError(exception, "An EST enrollment request failed");
        return Results.Text("Internal error while issuing the certificate.", Constants.TextPlainMimeType, Encoding.UTF8,
            StatusCodes.Status500InternalServerError);
    }

    /// <summary>
    /// Returns the DER bytes of the certification request in <paramref name="body"/>.
    /// </summary>
    /// <exception cref="FormatException">The body is neither PEM nor (url-safe) base64.</exception>
    public static byte[] DecodeCsr(string body)
    {
        if (PemEncoding.TryFind(body, out var fields))
        {
            return Convert.FromBase64String(body[fields.Base64Data]);
        }

        var builder = new StringBuilder(body.Length + 2);
        foreach (var c in body)
        {
            if (char.IsWhiteSpace(c))
            {
                continue;
            }

            builder.Append(c switch
            {
                '-' => '+',
                '_' => '/',
                _ => c
            });
        }

        switch (builder.Length % 4)
        {
            case 2:
                builder.Append("==");
                break;
            case 3:
                builder.Append('=');
                break;
            case 1:
                throw new FormatException("The request body is not valid base64.");
        }

        return Convert.FromBase64String(builder.ToString());
    }
}
