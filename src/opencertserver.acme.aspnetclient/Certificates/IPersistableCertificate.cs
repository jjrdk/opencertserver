namespace OpenCertServer.Acme.AspNetClient.Certificates
{
    /// <summary>
    /// A certificate which can be persisted as a stream of bytes
    /// </summary>
    public interface IPersistableCertificate : IAbstractCertificate
    {
        public byte[] RawData { get; }
    }
}