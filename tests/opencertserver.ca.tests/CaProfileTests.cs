namespace OpenCertServer.Ca.Tests;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Ca;
using Xunit;

public sealed class CaProfileTests : IDisposable
{
    private readonly CaProfile _profile;

    public CaProfileTests()
    {
        var (privateKey, certificate) = CreateCertificateAuthority("CN=Test Root CA");
        _profile = new CaProfile
        {
            Name = "test",
            PrivateKey = privateKey,
            CertificateChain = [certificate],
            PublishedCertificateChain = [],
            CertificateValidity = TimeSpan.FromDays(90)
        };
    }

    [Fact]
    public void CloseRolloverWindowRemovesRolloverCertificatesFromPublishedCertificateChain()
    {
        var originalThumbprint = _profile.CertificateChain[0].Thumbprint;
        var (newPrivateKey, newCertificate) = CreateCertificateAuthority("CN=Test Root CA");

        try
        {
            _profile.RollOver(newCertificate, newPrivateKey);
        }
        finally
        {
            newCertificate.Dispose();
        }

        Assert.Equal(4, _profile.PublishedCertificateChain.Count);

        _profile.CloseRolloverWindow();

        Assert.Single(_profile.PublishedCertificateChain);
        Assert.Equal(_profile.CertificateChain[0].Thumbprint, _profile.PublishedCertificateChain[0].Thumbprint);
        Assert.DoesNotContain(_profile.PublishedCertificateChain, cert =>
            string.Equals(cert.Thumbprint, originalThumbprint, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CloseRolloverWindowIsIdempotentWhenPublishedCertificatesAlreadyMatchActiveChain()
    {
        _profile.CloseRolloverWindow();
        _profile.CloseRolloverWindow();

        Assert.Single(_profile.PublishedCertificateChain);
        Assert.Equal(_profile.CertificateChain[0].Thumbprint, _profile.PublishedCertificateChain[0].Thumbprint);
        Assert.Single(_profile.PublishedCertificateChain.Select(cert => cert.Thumbprint).Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private static (RSA PrivateKey, X509Certificate2 Certificate) CreateCertificateAuthority(string subjectName)
    {
        var privateKey = RSA.Create(3072);
        var request = new CertificateRequest(
            subjectName,
            privateKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.AddYears(5));
        return (privateKey, certificate);
    }

    public void Dispose()
    {
        _profile.Dispose();
    }
}


