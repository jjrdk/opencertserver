using OpenCertServer.Est.Server.TrustAnchor;

namespace OpenCertServer.Est.Tests.Configuration;

using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.Extensions.Options;
using OpenCertServer.Ca.Utils.Ca;

public class ConfigureCertificateAuthenticationOptions :
    OpenCertServer.CertServer.ConfigureCertificateAuthenticationOptions,
    IPostConfigureOptions<CertificateAuthenticationOptions>
{
    public ConfigureCertificateAuthenticationOptions(
        IStoreCaProfiles profiles,
        IEstTrustAnchorProvider trustAnchorProvider)
        : base(profiles, trustAnchorProvider)
    {
    }

    public new void PostConfigure(string? name, CertificateAuthenticationOptions options)
    {
        base.PostConfigure(name, options);
        options.RevocationMode = X509RevocationMode.NoCheck;
    }
}
