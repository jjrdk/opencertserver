namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private static readonly Dictionary<string, string> SignatureAlgorithms = new()
    {
        ["sha256WithRSAEncryption"] = "1.2.840.113549.1.1.11",
        ["ecdsa-with-SHA256"] = "1.2.840.10045.4.3.2"
    };

    [When("^the CA signs a (RSA|ECDSA) certificate request with the \"(.+?)\" profile$")]
    public async Task WhenTheCaSignsACertificateRequestWithTheProfile(string requestKey, string profileName)
    {
        using AsymmetricAlgorithm key = requestKey == "RSA" ? RSA.Create(2048) : ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = key switch
        {
            RSA rsa => new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException()
        };

        var ca = _server.Services.GetRequiredService<ICertificateAuthority>();
        var response = await ca.SignCertificateRequest(request, profileName).ConfigureAwait(false);
        _scenarioContext["keyAlgorithmRequest"] = request;
        _scenarioContext["keyAlgorithmResponse"] = Assert.IsType<SignCertificateResponse.Success>(response);
    }

    [Then("the issued certificate carries the key of the request")]
    public void ThenTheIssuedCertificateCarriesTheKeyOfTheRequest()
    {
        var request = (CertificateRequest)_scenarioContext["keyAlgorithmRequest"];
        var issued = ((SignCertificateResponse.Success)_scenarioContext["keyAlgorithmResponse"]).Certificate;

        Assert.Equal(request.PublicKey.ExportSubjectPublicKeyInfo(), issued.PublicKey.ExportSubjectPublicKeyInfo());
    }

    [Then("^the issued certificate is signed with the (.+?) algorithm$")]
    public void ThenTheIssuedCertificateIsSignedWithTheAlgorithm(string algorithm)
    {
        var issued = ((SignCertificateResponse.Success)_scenarioContext["keyAlgorithmResponse"]).Certificate;

        Assert.Equal(SignatureAlgorithms[algorithm], issued.SignatureAlgorithm.Value);
    }

    [Then("^the issued certificate chains to the \"(.+?)\" CA$")]
    public async Task ThenTheIssuedCertificateChainsToTheCa(string profileName)
    {
        var issued = ((SignCertificateResponse.Success)_scenarioContext["keyAlgorithmResponse"]).Certificate;
        var profiles = _server.Services.GetRequiredService<IStoreCaProfiles>();
        var profile = await profiles.GetProfile(profileName).ConfigureAwait(false);

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        chain.ChainPolicy.CustomTrustStore.AddRange(profile.CertificateChain);

        Assert.True(
            chain.Build(issued),
            string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation.Trim())));
    }
}
