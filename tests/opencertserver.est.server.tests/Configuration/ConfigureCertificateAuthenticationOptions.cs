using OpenCertServer.Est.Server.TrustAnchor;

namespace OpenCertServer.Est.Tests.Configuration;

using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.Extensions.Options;
using Est.Server;

public class ConfigureCertificateAuthenticationOptions :
    OpenCertServer.CertServer.ConfigureCertificateAuthenticationOptions,
    IPostConfigureOptions<CertificateAuthenticationOptions>
{
    public ConfigureCertificateAuthenticationOptions(
        Func<string?, CancellationToken, Task<X509Certificate2Collection>> certificates,
        IEstTrustAnchorProvider trustAnchorProvider)
        : base(certificates, trustAnchorProvider)
    {
    }

    public new void PostConfigure(string? name, CertificateAuthenticationOptions options)
    {
        base.PostConfigure(name, options);
        options.RevocationMode = X509RevocationMode.NoCheck;
    }
}
