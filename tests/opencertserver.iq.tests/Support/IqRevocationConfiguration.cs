namespace OpenCertServer.Iq.Tests.Support;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Networks;

/// <summary>Disposable HTTPS OIDC discovery, signed identities and an HTTP CRL relay for CRL and EST IQ.</summary>
internal sealed class IqRevocationConfiguration
{
    public const string IssuerAlias = "issuer";
    public const string IssuerUrl = "https://issuer:8443";
    public const string Audience = "https://iq.test";
    public const string CrlUrl = "http://issuer:8080/ca/crl";

    private readonly byte[] _jwks;

    public IqRevocationConfiguration()
    {
        using var key = RSA.Create(2048);
        var parameters = key.ExportParameters(false);
        var kid = Guid.NewGuid().ToString("N");
        _jwks = JsonSerializer.SerializeToUtf8Bytes(new
        {
            keys = new[]
            {
                new { kty = "RSA", use = "sig", alg = "RS256", kid,
                    n = Base64Url(parameters.Modulus!), e = Base64Url(parameters.Exponent!) }
            }
        });
        AdminToken = Token("ca_admin");
        UserToken = Token("ca_reader");
        EnrollmentToken = Token("est_device", IqAuthorityConfiguration.EstIdentity);

        string Token(string role, string? name = null)
        {
            var now = DateTimeOffset.UtcNow;
            var header = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = "JWT", kid }));
            var payload = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new
            {
                iss = IssuerUrl,
                aud = Audience,
                sub = "iq-operator",
                unique_name = name,
                role,
                nbf = now.AddMinutes(-1).ToUnixTimeSeconds(),
                exp = now.AddHours(1).ToUnixTimeSeconds()
            }));
            var input = $"{header}.{payload}";
            return $"{input}.{Base64Url(key.SignData(Encoding.ASCII.GetBytes(input),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))}";
        }
    }

    public string AdminToken { get; }

    public string UserToken { get; }

    public string EnrollmentToken { get; }

    public ContainerBuilder Configure(ContainerBuilder builder, TestTlsPki tls) => builder
        .WithEnvironment("SSL_CERT_FILE", "/certs/iq-tls-root.crt")
        .WithResourceMapping(Encoding.ASCII.GetBytes(tls.RootPem),
            "/certs/iq-tls-root.crt", fileMode: Unix.FileMode644)
        .WithEnvironment("CaServer__CrlDistributionPoints__0", CrlUrl);

    public IContainer BuildIssuer(INetwork network, TestTlsPki tls) =>
        new ContainerBuilder("python:3.12-alpine")
            .WithNetwork(network)
            .WithNetworkAliases(IssuerAlias)
            .WithResourceMapping(Encoding.ASCII.GetBytes(tls.LeafPem),
                "/oidc/tls.crt", fileMode: Unix.FileMode644)
            .WithResourceMapping(Encoding.ASCII.GetBytes(tls.LeafKeyPem),
                "/oidc/tls.key", fileMode: Unix.FileMode600)
            .WithResourceMapping(Encoding.ASCII.GetBytes(tls.RootPem),
                "/oidc/root.crt", fileMode: Unix.FileMode644)
            .WithResourceMapping(JsonSerializer.SerializeToUtf8Bytes(new
            {
                issuer = IssuerUrl,
                jwks_uri = $"{IssuerUrl}/jwks.json",
                id_token_signing_alg_values_supported = new[] { "RS256" }
            }),
                "/oidc/.well-known/openid-configuration", fileMode: Unix.FileMode644)
            .WithResourceMapping(_jwks, "/oidc/jwks.json", fileMode: Unix.FileMode644)
            .WithCommand("python", "-u", "-c", """
                import os, ssl, threading, urllib.request
                from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
                os.chdir("/oidc")
                class CrlProxy(BaseHTTPRequestHandler):
                    def do_GET(self):
                        if self.path != "/ca/crl":
                            self.send_error(404)
                            return
                        try:
                            with urllib.request.urlopen("https://opencertserver:6001/ca/crl",
                                    context=ssl.create_default_context(cafile="root.crt"), timeout=15) as response:
                                body = response.read()
                                self.send_response(response.status)
                                self.send_header("Content-Type", response.headers["Content-Type"])
                                self.send_header("Content-Length", str(len(body)))
                                self.end_headers()
                                self.wfile.write(body)
                        except OSError as error:
                            self.log_error("CRL upstream failed: %s", error)
                            self.send_error(502)
                proxy = ThreadingHTTPServer(("0.0.0.0", 8080), CrlProxy)
                threading.Thread(target=proxy.serve_forever, daemon=True).start()
                class OidcHandler(SimpleHTTPRequestHandler):
                    def do_GET(self):
                        if self.path not in ("/.well-known/openid-configuration", "/jwks.json"):
                            self.send_error(404)
                            return
                        super().do_GET()
                server = ThreadingHTTPServer(("0.0.0.0", 8443), OidcHandler)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain("tls.crt", "tls.key")
                server.socket = context.wrap_socket(server.socket, server_side=True)
                server.serve_forever()
                """)
            .WithPortBinding(8443, true)
            .WithWaitStrategy(Wait.ForUnixContainer().UntilHttpRequestIsSucceeded(request => request
                .ForPort(8443).ForPath("/.well-known/openid-configuration").UsingTls()
                .UsingHttpMessageHandler(tls.CreateTrustingHandler())))
            .Build();

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
