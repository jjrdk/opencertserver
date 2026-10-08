using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.Extensions.Options;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

public class ConfigureTestCertificateAuthenticationOptions : ConfigureCertificateAuthenticationOptions,
                                                             IPostConfigureOptions<CertificateAuthenticationOptions>
{
    public ConfigureTestCertificateAuthenticationOptions(
        Func<string?, CancellationToken, Task<X509Certificate2Collection>> certificates)
        : base(certificates)
    {
    }

    public new void PostConfigure(string? name, CertificateAuthenticationOptions options)
    {
        base.PostConfigure(name, options);

        // Relaxing allowed types for testing purposes, as we may use self-signed certificates in tests.
        options.RevocationMode = X509RevocationMode.NoCheck;
    }
}
