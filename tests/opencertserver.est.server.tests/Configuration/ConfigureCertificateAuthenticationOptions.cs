using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils;

namespace OpenCertServer.Est.Tests.Configuration;

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.Extensions.Options;

public class ConfigureCertificateAuthenticationOptions : IPostConfigureOptions<CertificateAuthenticationOptions>
{
    private static readonly ImmutableDictionary<string, string> KnownPrefixes = ImmutableDictionary.CreateRange([
        KeyValuePair.Create(Oids.CommonName, ClaimTypes.Name),
        KeyValuePair.Create(Oids.EmailAddress, ClaimTypes.Email),
        KeyValuePair.Create(Oids.OrganizationalUnit, ClaimTypes.System),
        KeyValuePair.Create(Oids.Organization, "org"),
        KeyValuePair.Create(Oids.LocalityName, ClaimTypes.Locality),
        KeyValuePair.Create(Oids.Surname, ClaimTypes.Surname),
        KeyValuePair.Create(Oids.GivenName, ClaimTypes.GivenName),
        KeyValuePair.Create(Oids.CountryOrRegionName, ClaimTypes.Country)
    ]);

    private readonly Func<string?, X509Certificate2Collection> _certificates;

    public ConfigureCertificateAuthenticationOptions(Func<string?, X509Certificate2Collection> certificates)
    {
        _certificates = certificates;
    }

    public void PostConfigure(string? name, CertificateAuthenticationOptions options)
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var claims = context.HttpContext.Connection.ClientCertificate!.SubjectName
                    .EnumerateRelativeDistinguishedNames()
                    .Where(x => KnownPrefixes.ContainsKey(x.GetSingleElementType().Value!))
                    .Select(x => new Claim(KnownPrefixes[x.GetSingleElementType().Value!], x.GetSingleElementValue()!));
                context.Principal =
                    new ClaimsPrincipal(new ClaimsIdentity(claims,
                        CertificateAuthenticationDefaults.AuthenticationScheme));
                context.Success();
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
//                var profileName = context.HttpContext.Request.RouteValues["profileName"];
//                var certChain = context.HttpContext.RequestServices
//                    .GetRequiredService<Func<string?, X509Certificate2Collection>>();
//                var chainPolicy = new X509ChainPolicy
//                {
//                    TrustMode = X509ChainTrustMode.CustomRootTrust, VerificationTimeIgnored = true
//                };
//                chainPolicy.CustomTrustStore.AddRange(certChain(profileName as string));
//                chainPolicy.ExtraStore.AddRange(certChain(profileName as string));
//                var chain = new X509Chain { ChainPolicy = chainPolicy };
                var clientCertificate = context.HttpContext.Connection.ClientCertificate!;
//                var built = chain.Build(clientCertificate);
//                if (!built)
//                {
//                    context.Fail("Certificate chain validation failed: " +
//                        string.Join(", ", chain.ChainStatus.Select(x => x.StatusInformation)));
//                    return Task.CompletedTask;
//                }

                var claims = clientCertificate.SubjectName
                    .EnumerateRelativeDistinguishedNames()
                    .Where(x => KnownPrefixes.ContainsKey(x.GetSingleElementType().Value!))
                    .Select(x => new Claim(KnownPrefixes[x.GetSingleElementType().Value!], x.GetSingleElementValue()!));
                context.Principal =
                    new ClaimsPrincipal(new ClaimsIdentity(claims,
                        CertificateAuthenticationDefaults.AuthenticationScheme));
                context.Success();
                return Task.CompletedTask;
            }
        };
    }
}
