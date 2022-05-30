namespace OpenCertServer.Acme.AspNetClient.Certificates
{
    using System;

    /// <summary>
    /// The most generic form of certificate, metadata provision only
    /// </summary>
    public interface IAbstractCertificate
    {
        public DateTime NotAfter { get; }
        public DateTime NotBefore { get; }
        string Thumbprint { get; }
    }
}