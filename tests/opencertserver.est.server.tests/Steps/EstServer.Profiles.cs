namespace OpenCertServer.Est.Tests.Steps;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509Extensions;
using OpenCertServer.Est.Tests;
using Reqnroll;
using Xunit;

/// <summary>Steps for <c>CaProfilePolicies.feature</c>: content the CA profile fixes.</summary>
public partial class EstServer
{
    [Given("""^a certificate server whose "rsa" profile is configured with:$""")]
    public async Task GivenACertificateServerWhoseRsaProfileIsConfiguredWith(DataTable settings)
    {
        var values = settings.Rows.ToDictionary(r => r["setting"], r => r["value"], StringComparer.OrdinalIgnoreCase);
        _context[nameof(ProfileSettings)] = new ProfileSettings(
            AllowedCsrExtensions: Split(values.GetValueOrDefault("AllowedCsrExtensions")),
            CertificatePolicies: Split(values.GetValueOrDefault("CertificatePolicies")),
            KeyUsage: values.TryGetValue("KeyUsage", out var keyUsage)
                ? Enum.Parse<X509KeyUsageFlags>(keyUsage, ignoreCase: true)
                : null,
            ExtendedKeyUsages: Split(values.GetValueOrDefault("ExtendedKeyUsages")));
        await GivenACertificateServerThatCompliesWithEstRfc().ConfigureAwait(false);
    }

    [When("""^a client submits a rsa CSR to the "rsa" profile that asks for the policy "([^"]+)"$""")]
    public Task WhenAClientSubmitsACsrThatAsksForThePolicy(string policy) =>
        SubmitRsaCsrAsync(request =>
            request.CertificateExtensions.Add(new X509CertificatePoliciesExtension([policy])));

    [When("""^a client submits a rsa CSR to the "rsa" profile that asks for the key usage "([^"]+)"$""")]
    public Task WhenAClientSubmitsACsrThatAsksForTheKeyUsage(string keyUsage) =>
        SubmitRsaCsrAsync(request =>
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(Enum.Parse<X509KeyUsageFlags>(keyUsage, ignoreCase: true), false)));

    [When("""^a client submits a rsa CSR to the "rsa" profile that asks for the extended key usage "([^"]+)"$""")]
    public Task WhenAClientSubmitsACsrThatAsksForTheExtendedKeyUsage(string eku) =>
        SubmitRsaCsrAsync(request =>
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(eku)], false)));

    [When("""^a client submits a rsa CSR to the "rsa" profile that asks for a CA certificate$""")]
    public Task WhenAClientSubmitsACsrThatAsksForACaCertificate() =>
        SubmitRsaCsrAsync(request =>
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        });

    [Then("the issued certificate carries no certificatePolicies extension")]
    public void ThenTheIssuedCertificateCarriesNoCertificatePoliciesExtension()
    {
        Assert.DoesNotContain(Issued().Extensions.Cast<X509Extension>(), e => e.Oid?.Value == Oids.CertPolicies);
    }

    [Then("""^the issued certificate carries exactly the certificate policies "([^"]+)"$""")]
    public void ThenTheIssuedCertificateCarriesExactlyTheCertificatePolicies(string policies)
    {
        var extension = Assert.Single(Issued().Extensions.Cast<X509Extension>(), e => e.Oid?.Value == Oids.CertPolicies);
        var read = new X509CertificatePoliciesExtension(extension, extension.Critical);
        Assert.Equal(Split(policies), read.PolicyIdentifiers);
    }

    [Then("""^the issued certificate's key usage is exactly "([^"]+)" and critical$""")]
    public void ThenTheIssuedCertificatesKeyUsageIsExactlyAndCritical(string keyUsage)
    {
        var extension = Assert.Single(Issued().Extensions.OfType<X509KeyUsageExtension>());
        Assert.Equal(Enum.Parse<X509KeyUsageFlags>(keyUsage, ignoreCase: true), extension.KeyUsages);
        Assert.True(extension.Critical);
    }

    [Then("""^the issued certificate's extended key usages are exactly "([^"]+)"$""")]
    public void ThenTheIssuedCertificatesExtendedKeyUsagesAreExactly(string ekus)
    {
        var extension = Assert.Single(Issued().Extensions.OfType<X509EnhancedKeyUsageExtension>());
        Assert.Equal(Split(ekus), extension.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).OfType<string>().ToArray());
    }

    [Then("the issued certificate is a CA certificate")]
    public void ThenTheIssuedCertificateIsACaCertificate()
    {
        var extension = Assert.Single(Issued().Extensions.OfType<X509BasicConstraintsExtension>());
        Assert.True(extension.CertificateAuthority);
    }

    /// <summary>Enrolls with a client certificate of the rsa profile and a CSR shaped by <paramref name="shape"/>.</summary>
    private async Task SubmitRsaCsrAsync(Action<CertificateRequest> shape)
    {
        using var rsa = RSA.Create();
        var clientCertificate = await GetCertificate(rsa).ConfigureAwait(false);
        var request = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        shape(request);
        var (error, cert) = await SubmitSimpleEnrollAsync(request, "rsa", clientCertificate).ConfigureAwait(false);
        Assert.True(error is null, error);
        _context["enrolledCertificate"] = cert;
    }

    private X509Certificate2 Issued() => ((X509Certificate2Collection)_context["enrolledCertificate"]!)[0];

    private static IReadOnlyList<string>? Split(string? value) =>
        value is null
            ? null
            : value.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
