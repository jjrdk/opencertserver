namespace OpenCertServer.Acme.AspNetClient.Certificates
{
    public enum CertificateRenewalStatus
    {
        Unchanged,
        LoadedFromStore,
        Renewed
    }
}