namespace OpenCertServer.Est.Server.Handlers;

using System.Security.Cryptography;
using System.Text;

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
