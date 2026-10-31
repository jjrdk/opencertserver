using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.Extensions.Options;
using OpenCertServer.Est.Server;
using OpenCertServer.Est.Server.TrustAnchor;
using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

public class ConfigureTestCertificateAuthenticationOptions :
    ConfigureCertificateAuthenticationOptions,
    IPostConfigureOptions<CertificateAuthenticationOptions>
{
    public ConfigureTestCertificateAuthenticationOptions(
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
