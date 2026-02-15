namespace OpenCertServer.CertServer;

using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.Extensions.Options;

public class ConfigureCertificateAuthenticationOptions : IPostConfigureOptions<CertificateAuthenticationOptions>
{
    private static readonly ImmutableDictionary<string, string> KnownPrefixes = ImmutableDictionary.CreateRange([
        KeyValuePair.Create("CN", ClaimTypes.Name),
        KeyValuePair.Create("E", ClaimTypes.Email),
        KeyValuePair.Create("OU", ClaimTypes.System),
        KeyValuePair.Create("O", "org"),
        KeyValuePair.Create("L", ClaimTypes.Locality),
        KeyValuePair.Create("SN", ClaimTypes.Surname),
        KeyValuePair.Create("GN", ClaimTypes.GivenName),
        KeyValuePair.Create("C", ClaimTypes.Country)
    ]);

    private readonly X509Certificate2Collection _certificates;

    public ConfigureCertificateAuthenticationOptions(X509Certificate2Collection certificates)
    {
        _certificates = certificates;
    }

    public void PostConfigure(string? name, CertificateAuthenticationOptions options)
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.AdditionalChainCertificates = _certificates;
        options.CustomTrustStore = _certificates;
        options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var claims = context.ClientCertificate.SubjectName.Name
                    .Split(",", StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                    .Select(x => (x[..x.IndexOf('=')], x[(x.IndexOf('=') + 1)..]))
                    .Where(x => KnownPrefixes.ContainsKey(x.Item1))
                    .Select(x => new Claim(x.Item1, x.Item2));
                context.Principal =
                    new ClaimsPrincipal(new ClaimsIdentity(claims,
                        CertificateAuthenticationDefaults.AuthenticationScheme));
                context.Success();
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                var claims = context.HttpContext.Connection.ClientCertificate!.SubjectName.Name
                    .Split(",", StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                    .Select(x => (x[..x.IndexOf('=')], x[(x.IndexOf('=') + 1)..]))
                    .Where(x => KnownPrefixes.ContainsKey(x.Item1))
                    .Select(x => new Claim(x.Item1, x.Item2));
                context.Principal =
                    new ClaimsPrincipal(new ClaimsIdentity(claims,
                        CertificateAuthenticationDefaults.AuthenticationScheme));
                context.Success();
                return Task.CompletedTask;
            }
        };
    }
}
