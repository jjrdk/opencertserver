namespace OpenCertServer.Iq.Tests.Support;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;

/// <summary>File-backed issuing profiles and an ephemeral EST identity for authority-information, CRL and EST IQ.</summary>
internal sealed class IqAuthorityConfiguration(
    string authority = "https://iq.test", bool publishCsrTemplate = false, bool qualifyProfileIssuance = false)
{
    public const string EstIdentity = "est.example.com";
    public const string OcspUrl = "http://localhost:6001/ocsp";
    public const string CaIssuersUrl = "http://localhost:6001/ca/ca.pem";
    public const string CrlUrl = "http://localhost:6001/ca/crl.pem";
    public const string PolicyOid = "1.3.6.1.4.1.9999.1";
    public const string ExtendedKeyUsages = "TLS Web Server Authentication, TLS Web Client Authentication";

    public string EstPassword { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));

    public string[] ServerArguments =>
    [
        "--authority", authority,
        "--audience", "https://iq.test",
        "--rsa", "/certs/rsa.crt", "--rsa-key", "/certs/rsa.key",
        "--ec", "/certs/ecdsa.crt", "--ec-key", "/certs/ecdsa.key",
        "--port", "6001"
    ];

    public ContainerBuilder Configure(ContainerBuilder builder)
    {
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        builder = AddIssuer(builder, "rsa",
            new CertificateRequest("CN=IQ RSA Issuer", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            rsa.ExportPkcs8PrivateKeyPem());
        builder = AddIssuer(builder, "ecdsa",
            new CertificateRequest("CN=IQ ECDSA Issuer", ec, HashAlgorithmName.SHA256),
            ec.ExportPkcs8PrivateKeyPem());

        // The host accepts the documented PBKDF2-SHA256 users-file format, not plaintext passwords.
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(EstPassword, salt, 600_000, HashAlgorithmName.SHA256, 32);
        var passwordHash = $"pbkdf2-sha256$600000${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
        builder = builder
            .WithEnvironment("Est__BasicAuth__UsersFile", "/certs/est-users")
            .WithResourceMapping(Encoding.ASCII.GetBytes($"{EstIdentity}:{passwordHash}\n"),
                "/certs/est-users", fileMode: Unix.FileMode644)
            .WithEnvironment("CaServer__OCSP__0", OcspUrl)
            .WithEnvironment("CaServer__CaIssuers__0", CaIssuersUrl)
            .WithEnvironment("CaServer__CrlDistributionPoints__0", CrlUrl);

        if (qualifyProfileIssuance)
        {
            foreach (var profile in new[] { "rsa", "ecdsa" })
            {
                builder = builder
                    .WithEnvironment($"{profile}__KeyUsage", "KeyEncipherment,DataEncipherment")
                    .WithEnvironment($"{profile}__ExtendedKeyUsages__0", "1.3.6.1.5.5.7.3.1")
                    .WithEnvironment($"{profile}__ExtendedKeyUsages__1", "1.3.6.1.5.5.7.3.3")
                    .WithEnvironment($"{profile}__CertificatePolicies__0", "1.3.6.1.4.1.999");
            }
        }
        else
        {
            builder = builder
                .WithEnvironment("rsa__ExtendedKeyUsages__0", "1.3.6.1.5.5.7.3.1")
                .WithEnvironment("rsa__ExtendedKeyUsages__1", "1.3.6.1.5.5.7.3.2")
                .WithEnvironment("rsa__CertificatePolicies__0", PolicyOid);
        }

        // CsrAttrs containing one RFC 9908 version-0 template with an unfilled commonName RDN.
        return publishCsrTemplate
            ? builder.WithEnvironment("Est__CsrAttributesFile", "/certs/csrattrs.der")
                .WithResourceMapping(Convert.FromHexString("3010300E0201003009310730050603550403"),
                    "/certs/csrattrs.der", fileMode: Unix.FileMode644)
            : builder;
    }

    private static ContainerBuilder AddIssuer(
        ContainerBuilder builder, string name, CertificateRequest request, string keyPem)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
        return builder
            .WithResourceMapping(Encoding.ASCII.GetBytes(certificate.ExportCertificatePem()),
                $"/certs/{name}.crt", fileMode: Unix.FileMode644)
            .WithResourceMapping(Encoding.ASCII.GetBytes(keyPem),
                $"/certs/{name}.key", fileMode: Unix.FileMode644);
    }
}
