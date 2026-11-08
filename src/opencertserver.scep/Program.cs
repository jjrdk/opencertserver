using OpenCertServer.Ca.Client;
using OpenCertServer.Contrib.Intune;
using OpenCertServer.Scep.Server;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// The SCEP RA cert is an identity of the SCEP host itself, just like the ACME RA cert.
// It is loaded from --scep-ra / --scep-ra-key, or a transient one is made when no key is
// supplied. The SCEP host is only a transport, so the transient default matches ACME.
var raCertificate = LoadRaCertificate(args);
builder.Services.AddSingleton(raCertificate);

// Backing CA over trusted HTTPS: the SCEP host holds no CA key. It talks to the CA
// exactly like the RA and ACME hosts, which is what makes SCEP deployable on its own.
builder.Services.AddCaClient(builder.Configuration);

// The SCEP challenge: Intune when configured, otherwise a shared secret. PKIOperation
// issues nothing until a challenge is configured.
var scepSection = builder.Configuration.GetSection("Scep");
var intuneConfigured = scepSection.Exists() && scepSection.GetSection("Intune").Exists();
var challenge = scepSection["Challenge"];
builder.Services.AddScepServer(
    new ScepServerOptions
    {
        RaCertificate = raCertificate,
        DefaultProfile = scepSection[nameof(ScepServerOptions.DefaultProfile)]
    },
    challenge is { Length: > 0 }
        ? new SharedSecretChallengeValidator(challenge)
        : new NotConfiguredChallengeValidator());

if (intuneConfigured)
{
    // Intune replaces the "not configured" validator and adds the revocation sync.
    builder.Services.AddIntune(builder.Configuration);
    builder.Services.AddAuthentication("Bearer")
        .AddJwtBearer()
        .AddCertificate();
}

var app = builder.Build();
app.MapScepServer();
if (intuneConfigured)
{
    app.MapIntuneSync();
}

app.Run();

// Load the RA cert from --scep-ra / --scep-ra-key, or make a transient one.
static X509Certificate2 LoadRaCertificate(string[] args)
{
    var certPath = args.Length > 0 && args[0] == "--scep-ra" ? args[1] : null;
    var keyPath = args.Length > 2 && args[2] == "--scep-ra-key" ? args[3] : null;

    if (certPath is not null && keyPath is not null)
    {
        return X509Certificate2.CreateFromPemFile(
            Path.GetFullPath(certPath),
            Path.GetFullPath(keyPath));
    }

    using var rsa = RSA.Create(2048);
    var request = new CertificateRequest(
        "CN=OpenCertServer SCEP RA",
        rsa,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);

    request.CertificateExtensions.Add(
        new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(
        new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            true));

    using var certificate = request.CreateSelfSigned(
        DateTime.UtcNow.AddDays(-1),
        DateTime.UtcNow.AddDays(30));

    return certificate.CopyWithPrivateKey(rsa);
}
