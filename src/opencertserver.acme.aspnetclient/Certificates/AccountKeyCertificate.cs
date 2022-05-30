namespace OpenCertServer.Acme.AspNetClient.Certificates
{
    using System;
    using System.Text;
    using global::Certes;

    /// <summary>
    /// The type of certificate used to store a Let's Encrypt account key
    /// </summary>
    public class AccountKeyCertificate : IPersistableCertificate, IKeyCertificate
    {
        public AccountKeyCertificate(IKey key)
        {
            Key = key;
            var text = key.ToPem();
            RawData = Encoding.UTF8.GetBytes(text);
        }

        public AccountKeyCertificate(byte[] bytes)
        {
            RawData = bytes;
            var text = Encoding.UTF8.GetString(bytes);
            Key = KeyFactory.FromPem(text);
        }

        public DateTime NotAfter
        {
            get { throw new InvalidOperationException("No metadata available for key certificate"); }
        }

        public DateTime NotBefore
        {
            get { throw new InvalidOperationException("No metadata available for key certificate"); }
        }

        public string Thumbprint
        {
            get { throw new InvalidOperationException("No metadata available for key certificate"); }
        }

        public byte[] RawData { get; }
        public IKey? Key { get; }
    }
}