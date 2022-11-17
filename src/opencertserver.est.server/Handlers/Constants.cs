namespace OpenCertServer.Est.Server.Handlers;

internal static class Constants
{
    public const string EndPkcs7 = "-----END PKCS7-----";
    public const string BeginPkcs7 = "-----BEGIN PKCS7-----";
    public const string Pkcs7MimeType = "application/pkcs7-mime";
    public const string PemMimeType = "application/x-pem-file";
    public const string TextPlainMimeType = "text/plain";
}