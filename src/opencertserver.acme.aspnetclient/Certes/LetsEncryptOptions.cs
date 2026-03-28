namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using global::CertesSlim.Acme;

public sealed class LetsEncryptOptions : AcmeOptions
{
    /// <summary>
    /// Gets the uri which will be used to talk to LetsEncrypt servers.
    /// </summary>
    public override Uri AcmeServerUri
    {
        get { return UseStaging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2; }
    }
}
