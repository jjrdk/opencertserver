using System.Net.Http.Headers;
using System.Text;

namespace OpenCertServer.Est.Server.Response;

internal sealed class EstMultipartBase64Content : StringContent
{
    public EstMultipartBase64Content(
        string base64Text,
        string mediaType,
        bool includeBase64TransferEncoding = true,
        string? smimeType = null)
        : base(base64Text, Encoding.ASCII)
    {
        Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        if (!string.IsNullOrWhiteSpace(smimeType))
        {
            Headers.ContentType.Parameters.Add(new NameValueHeaderValue("smime-type", $"\"{smimeType}\""));
        }

        if (includeBase64TransferEncoding)
        {
            Headers.TryAddWithoutValidation("Content-Transfer-Encoding", "base64");
        }
    }
}

