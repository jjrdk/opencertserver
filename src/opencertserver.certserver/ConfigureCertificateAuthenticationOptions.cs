using OpenCertServer.Est.Server.TrustAnchor;

namespace OpenCertServer.CertServer;

using System.Collections.Immutable;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Est.Server;
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

    private readonly Func<string?, CancellationToken, Task<X509Certificate2Collection>> _certificates;
    private readonly IEstTrustAnchorProvider _trustAnchorProvider;

    public ConfigureCertificateAuthenticationOptions(
        Func<string?, CancellationToken, Task<X509Certificate2Collection>> certificates,
        IEstTrustAnchorProvider trustAnchorProvider)
    {
        _certificates = certificates;
        _trustAnchorProvider = trustAnchorProvider;
    }

    public void PostConfigure(string? name, CertificateAuthenticationOptions options)
    {
        options.AllowedCertificateTypes = CertificateTypes.Chained;
        options.ValidateCertificateUse = true;
        options.ValidateValidityPeriod = true;
        var certificates = _certificates(null, CancellationToken.None).GetAwaiter().GetResult();
        options.AdditionalChainCertificates.Clear();
        options.AdditionalChainCertificates.AddRange(certificates);
        options.CustomTrustStore.Clear();
        options.CustomTrustStore.AddRange(certificates);
        foreach (var anchor in _trustAnchorProvider.TrustAnchors)
        {
            options.CustomTrustStore.Add(anchor);
        }

        options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = async context =>
            {
                var error = await ValidateCertificateAsync(
                    context.HttpContext,
                    context.ClientCertificate,
                    options.RevocationMode,
                    options.RevocationFlag).ConfigureAwait(false);
                if (error is not null)
                {
                    context.Fail(error);
                    return;
                }

                context.Principal = CreatePrincipal(context.ClientCertificate);
                context.Success();
            },
            OnAuthenticationFailed = async context =>
            {
                var certificate = context.HttpContext.Connection.ClientCertificate;
                if (certificate is null)
                {
                    context.Fail("The client certificate is unavailable.");
                    return;
                }

                var error = await ValidateCertificateAsync(
                    context.HttpContext,
                    certificate,
                    options.RevocationMode,
                    options.RevocationFlag).ConfigureAwait(false);
                if (error is not null)
                {
                    context.Fail(error);
                    return;
                }

                context.Principal = CreatePrincipal(certificate);
                context.Success();
            }
        };
    }

    private async Task<string?> ValidateCertificateAsync(
        HttpContext httpContext,
        X509Certificate2 certificate,
        X509RevocationMode revocationMode,
        X509RevocationFlag revocationFlag)
    {
        if (certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData))
        {
            return "A self-issued certificate cannot authenticate a client.";
        }

        if (certificate.Extensions.OfType<X509BasicConstraintsExtension>()
            .Any(extension => extension.CertificateAuthority))
        {
            return "A CA certificate cannot authenticate as an EST client.";
        }

        var profileName = httpContext.Request.RouteValues["profileName"] as string;
        var caCertificates = await _certificates(profileName, httpContext.RequestAborted).ConfigureAwait(false);
        var isEstRequest = IsEstRequest(httpContext.Request.Path);
        var chainPolicy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = revocationMode,
            RevocationFlag = revocationFlag,
            VerificationFlags = X509VerificationFlags.NoFlag
        };
        chainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
        chainPolicy.CustomTrustStore.AddRange(caCertificates);
        chainPolicy.ExtraStore.AddRange(caCertificates);
        if (isEstRequest)
        {
            foreach (var anchor in _trustAnchorProvider.TrustAnchors)
            {
                chainPolicy.CustomTrustStore.Add(anchor);
            }

            foreach (var extraCertificate in _trustAnchorProvider.AdditionalChainCertificates)
            {
                chainPolicy.ExtraStore.Add(extraCertificate);
            }
        }

        using var chain = new X509Chain { ChainPolicy = chainPolicy };
        var isTrusted = chain.Build(certificate);
        var chainErrors = isTrusted
            ? string.Empty
            : string.Join(", ", chain.ChainStatus.Select(status => status.StatusInformation.Trim()));
        foreach (var element in chain.ChainElements)
        {
            element.Certificate.Dispose();
        }

        if (isTrusted)
        {
            return null;
        }

        return string.IsNullOrEmpty(chainErrors)
            ? "Certificate chain validation failed."
            : $"Certificate chain validation failed: {chainErrors}";
    }

    private static bool IsEstRequest(PathString path) =>
        path.StartsWithSegments("/.well-known/est", StringComparison.OrdinalIgnoreCase);

    private static ClaimsPrincipal CreatePrincipal(X509Certificate2 certificate)
    {
        var claims = certificate.SubjectName.Name
            ?.Split(",", StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(x =>
            {
                var separator = x.IndexOf('=');
                return separator < 0 ? (string.Empty, string.Empty) : (x[..separator], x[(separator + 1)..]);
            })
            .Where(x => KnownPrefixes.ContainsKey(x.Item1))
            .Select(x => new Claim(KnownPrefixes[x.Item1], x.Item2))
            .Append(new Claim("sub", certificate.Thumbprint))
            ?? [new Claim("sub", certificate.Thumbprint)];

        return new ClaimsPrincipal(new ClaimsIdentity(
            claims,
            CertificateAuthenticationDefaults.AuthenticationScheme));
    }
}
