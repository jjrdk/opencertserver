namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Adapts the sibling YARP pentest probes to the shared certserver IQ topology.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class PenetrationSteps(
    ScenarioContext context, AcmeScenarioState state, IReqnrollOutputHelper output)
{
    public const string FeatureTitle = "Certificate server perimeter security from a Linux scanner";

    private const string TrustRoot = "/usr/local/share/ca-certificates/iq-tls-root.crt";
    private const string Host = IqAcmeEnvironment.ServerAlias;
    private const int Port = IqAcmeEnvironment.ServerPort;
    private readonly IqAcmeEnvironment _environment = context.Get<IqAcmeEnvironment>();
    private readonly List<(bool Secure, string Requirement, string Evidence)> _observations = [];

    [When("the Linux scanner runs certificate server penetration probe {string}")]
    public async Task RunProbe(string id)
    {
        switch (id)
        {
            case "TLS-01": await Protocol("-tls1", false).ConfigureAwait(false); break;
            case "TLS-02": await Protocol("-tls1_1", false).ConfigureAwait(false); break;
            case "TLS-03": await Protocol("-tls1_2", true).ConfigureAwait(false); break;
            case "TLS-04": await Protocol("-tls1_3", true).ConfigureAwait(false); break;
            case "TLS-05": await Protocol("-tls1_2", false, "AES128-SHA").ConfigureAwait(false); break;
            case "TLS-06": await CipherInventory().ConfigureAwait(false); break;
            case "HTTP-01": await Redirect().ConfigureAwait(false); break;
            case "HTTP-02": await Hsts().ConfigureAwait(false); break;
            case "HTTP-03": await Banner().ConfigureAwait(false); break;
            case "HTTP-04": await Trace().ConfigureAwait(false); break;
            case "HTTP-05": await Authorization().ConfigureAwait(false); break;
            case "HTTP-06": await HostValidation().ConfigureAwait(false); break;
            case "HTTP-07": await CertificateHeader().ConfigureAwait(false); break;
            case "HTTP-08": await AmbiguousFraming().ConfigureAwait(false); break;
            case "HTTP-09": await RejectedPaths().ConfigureAwait(false); break;
            case "HTTP-10": await HeaderLimit().ConfigureAwait(false); break;
            default: throw new ArgumentOutOfRangeException(nameof(id), id, "Unknown penetration probe.");
        }
    }

    [Then("the certificate server security requirement is satisfied")]
    public void VerifyRequirement()
    {
        Assert.NotEmpty(_observations);
        var failures = _observations.Where(o => !o.Secure).ToArray();
        Assert.True(failures.Length == 0,
            string.Join("\n\n", failures.Select(o => $"{o.Requirement}\n{o.Evidence}")));
    }

    private void Observe(bool secure, string requirement, string evidence)
    {
        _observations.Add((secure, requirement, evidence));
        output.WriteLine($"{(secure ? "PASS" : "FINDING")}: {requirement}\n{evidence}");
    }

    private async Task<ExecResult> Tool(string executable, params string[] arguments)
    {
        var seconds = executable == "nmap" ? 90 : 20;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(seconds + 10));
        // Cancellation of Docker exec does not kill the tool; bound execution inside Linux too.
        var result = await _environment.Client.ExecAsync(
            ["/bin/sh", "-c", "exec \"$@\" < /dev/null", "pentest",
                "timeout", "--signal=KILL", $"{seconds}s", executable, .. arguments], timeout.Token)
            .ConfigureAwait(false);
        state.LastExec = result;
        if (result.ExitCode is null or 124 or 137)
        {
            throw new TimeoutException($"{executable} did not complete within {seconds}s:\n{result.Stdout}\n{result.Stderr}");
        }

        return result;
    }

    private async Task<Reply> Request(string path = "/health", string scheme = "https", params string[] arguments)
    {
        if (!path.StartsWith('/') || path.StartsWith("//", StringComparison.Ordinal) || path.Contains('#'))
        {
            throw new ArgumentException("Probe path must stay on the isolated certificate server.", nameof(path));
        }

        var port = scheme == "https" ? Port : IqAcmeEnvironment.HttpPort;
        var result = await Tool("curl", ["--silent", "--show-error", "--http1.1", "--max-time", "15",
            "--cacert", TrustRoot, "--dump-header", "-", "--path-as-is",
            .. arguments, $"{scheme}://{Host}:{port}{path}"]).ConfigureAwait(false);
        Assert.True(result.ExitCode == 0, $"curl failed ({result.ExitCode}):\n{result.Stdout}\n{result.Stderr}");
        return Reply.Parse(result.Stdout);
    }

    private async Task Protocol(string protocol, bool allowed, string? cipher = null)
    {
        var arguments = new List<string>
        {
            "s_client", "-connect", $"{Host}:{Port}", "-servername", Host,
            "-verify_hostname", Host, "-verify_return_error", "-CAfile", TrustRoot, "-brief", protocol
        };
        if (!allowed)
        {
            arguments.AddRange(["-cipher", (cipher ?? "ALL") + ":@SECLEVEL=0"]);
        }

        var result = await Tool("openssl", arguments.ToArray()).ConfigureAwait(false);
        var evidence = result.Stdout + result.Stderr;
        var negotiated = result.ExitCode == 0 &&
                         evidence.Contains("CONNECTION ESTABLISHED", StringComparison.OrdinalIgnoreCase) &&
                         evidence.Contains("Verification: OK", StringComparison.OrdinalIgnoreCase);
        var rejected = result.ExitCode != 0 &&
                       (evidence.Contains("alert protocol version", StringComparison.OrdinalIgnoreCase) ||
                        evidence.Contains("alert handshake failure", StringComparison.OrdinalIgnoreCase));
        Assert.True(negotiated || rejected, $"Inconclusive OpenSSL probe (not peer rejection):\n{evidence}");
        if (negotiated)
        {
            Assert.Contains(protocol == "-tls1_3" ? "TLSv1.3" :
                protocol == "-tls1_2" ? "TLSv1.2" :
                protocol == "-tls1_1" ? "TLSv1.1" : "TLSv1", evidence, StringComparison.Ordinal);
        }

        Observe(allowed ? negotiated : rejected,
            $"{protocol} {cipher} must be {(allowed ? "supported with valid TLS identity" : "rejected")}", evidence);
    }

    private async Task CipherInventory()
    {
        var result = await Tool("nmap", "--unprivileged", "-sT", "-Pn", "-n", "--host-timeout", "60s",
            "--script-timeout", "45s", "-p", Port.ToString(CultureInfo.InvariantCulture),
            "--script", "+ssl-enum-ciphers", "--script-args", $"tls.servername={Host}", "-oX", "-", Host)
            .ConfigureAwait(false);
        Assert.True(result.ExitCode == 0, $"Nmap failed:\n{result.Stdout}\n{result.Stderr}");
        var xml = XDocument.Parse(result.Stdout);
        var port = Assert.Single(xml.Descendants("port"),
            p => (string?)p.Attribute("portid") == Port.ToString(CultureInfo.InvariantCulture));
        Assert.Equal("open", (string?)port.Element("state")?.Attribute("state"));
        var script = Assert.Single(port.Elements("script"), s => (string?)s.Attribute("id") == "ssl-enum-ciphers");
        var suites = script.Descendants("table").Where(t => (string?)t.Attribute("key") == "ciphers")
            .Descendants("elem").Where(e => (string?)e.Attribute("key") == "name")
            .Select(e => e.Value).Distinct().ToArray();
        Assert.NotEmpty(suites);
        Assert.Contains(script.Elements("table"), t => (string?)t.Attribute("key") == "TLSv1.2");
        var weak = suites.Where(s => s.StartsWith("TLS_RSA_", StringComparison.Ordinal) ||
            new[] { "_CBC_", "_RC4_", "_3DES_", "_DES_", "_NULL_", "_EXPORT_", "_anon_", "_MD5" }
                .Any(fragment => s.Contains(fragment, StringComparison.OrdinalIgnoreCase))).ToArray();
        var legacy = script.Elements("table").Any(t => (string?)t.Attribute("key") is "SSLv3" or "TLSv1.0" or "TLSv1.1");
        Observe(weak.Length == 0 && !legacy,
            "Nmap must enumerate TLS 1.2 ciphers without legacy protocols or weak suites",
            $"Enumerated {suites.Length} suites; disallowed: {string.Join(", ", weak)}\n{script.Attribute("output")?.Value}");
    }

    private async Task Redirect()
    {
        foreach (var method in new[] { "GET", "POST", "PUT" })
        {
            const string path = "/pentest%20redirect?x=one%2Ftwo";
            var reply = await Request(path, "http", "--request", method,
                "--header", "X-Forwarded-Proto: https",
                "--header", "X-Forwarded-Host: attacker.invalid", "--data-binary", "pentest-body")
                .ConfigureAwait(false);
            Observe(reply.Status is 307 or 308 && reply.Header("Location") == $"https://{Host}:{Port}{path}",
                $"{method} over HTTP must redirect to the real HTTPS origin, preserving path and query", reply.Headers);
        }

        var health = await Request().ConfigureAwait(false);
        Observe(health.Status == 200 && health.Body == "Healthy", "Redirect target must be healthy over trusted TLS", health.Headers);
    }

    private async Task Hsts()
    {
        foreach (var path in new[] { "/health", "/directory", "/.well-known/est/cacerts", "/pentest-missing" })
        {
            var reply = await Request(path).ConfigureAwait(false);
            var maxAge = Regex.Match(reply.Header("Strict-Transport-Security"), @"(?:^|;)\s*max-age=(\d+)(?:;|$)",
                RegexOptions.IgnoreCase);
            Observe(maxAge.Success && long.TryParse(maxAge.Groups[1].Value, NumberStyles.None,
                    CultureInfo.InvariantCulture, out var age) && age >= 15_552_000,
                $"{path} must publish HSTS with max-age at least 15552000", reply.Headers);
        }
    }

    private async Task Banner()
    {
        foreach (var path in new[] { "/health", "/directory", "/.well-known/est/cacerts", "/pentest-missing" })
        {
            var reply = await Request(path).ConfigureAwait(false);
            Observe(reply.Header("Server").Length == 0 && reply.Header("X-Powered-By").Length == 0,
                $"{path} must not expose implementation banners", reply.Headers);
        }
    }

    private async Task Trace()
    {
        foreach (var path in new[] { "/directory", "/.well-known/est/cacerts", "/ca/csr" })
        {
            var reply = await Request(path, "https", "--request", "TRACE",
                "--header", "X-Pentest-Witness: must-not-be-reflected").ConfigureAwait(false);
            Observe(reply.Status == 405 && !reply.Body.Contains("must-not-be-reflected", StringComparison.Ordinal),
                $"TRACE {path} must receive 405 without reflecting request headers", reply.Headers);
        }
    }

    private async Task Authorization(params string[] headers)
    {
        foreach (var (path, method) in new[]
        {
            ("/ca/csr", "POST"), ("/ca/revoke?serial=01", "DELETE"),
            ("/.well-known/est/simpleenroll", "POST"), ("/.well-known/est/simplereenroll", "POST"),
            ("/.well-known/est/serverkeygen", "POST")
        })
        {
            foreach (var credential in new[] { "", "Bearer invalid-pentest-credential" })
            {
                var reply = await Request(path, "https", ["--request", method, "--header", "Content-Type: application/pkcs10",
                    "--header", $"Authorization: {credential}", .. headers, "--data-binary", "invalid-csr"])
                    .ConfigureAwait(false);
                Observe(reply.Status is 401 or 403,
                    $"{method} {path} must reject missing/invalid credentials before parsing the CSR", reply.Headers);
            }
        }
    }

    private async Task HostValidation()
    {
        foreach (var scheme in new[] { "http", "https" })
        {
            foreach (var path in new[] { "/health", "/directory", "/.well-known/est/cacerts" })
            {
                var reply = await Request(path, scheme, "--header", "Host: untrusted.example.invalid").ConfigureAwait(false);
                Observe(reply.Status is 400 or 403 or 421,
                    $"{scheme} {path} must reject unrecognized Host values before serving or redirecting", reply.Headers);
            }
        }
    }

    private async Task CertificateHeader()
    {
        // A syntactically valid, self-signed client certificate is stronger evidence than junk headers.
        var key = $"{state.WorkDir}/forged.key";
        var cert = $"{state.WorkDir}/forged.pem";
        var prepare = await _environment.ExecClientAsync($"mkdir -p '{state.WorkDir}'").ConfigureAwait(false);
        Assert.Equal(0, prepare.ExitCode);
        var create = await Tool("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=pentest-forged-identity")
            .ConfigureAwait(false);
        Assert.True(create.ExitCode == 0, create.Stderr);
        var der = await Tool("openssl", "x509", "-in", cert, "-outform", "DER", "-out", $"{state.WorkDir}/forged.der")
            .ConfigureAwait(false);
        Assert.True(der.ExitCode == 0, der.Stderr);
        var encoded = await Tool("base64", "-w0", $"{state.WorkDir}/forged.der").ConfigureAwait(false);
        Assert.Equal(0, encoded.ExitCode);
        await Authorization("--header", $"X-Client-Cert: {encoded.Stdout}",
            "--header", $"X-SSL-CERT: {encoded.Stdout}",
            "--header", "X-Forwarded-Client-Cert: By=pentest;Subject=\"CN=pentest-forged-identity\"",
            "--header", "X-Forwarded-User: ca_admin").ConfigureAwait(false);
    }

    private async Task AmbiguousFraming()
    {
        // RFC 9112 also permits normalizing CL+TE. This stricter perimeter gate requires rejection.
        // With no proxy/echo upstream, evidence is limited to responses on the same TLS connection.
        foreach (var headers in new[]
        {
            "Content-Length: 4\r\nTransfer-Encoding: chunked",
            "transfer-encoding: chunked\r\ncontent-length: 4",
            "Content-Length: 0\r\nContent-Length: 4"
        })
        {
            var body = headers.Contains("chunked", StringComparison.Ordinal) ? "0\r\n\r\n" : "test";
            var reply = await Raw($"POST /ca/csr HTTP/1.1\r\nHost: {Host}:{Port}\r\n{headers}\r\n\r\n{body}"
                + $"GET /health HTTP/1.1\r\nHost: {Host}:{Port}\r\nConnection: close\r\n\r\n")
                .ConfigureAwait(false);
            Observe(reply.Status is 400 or 501 &&
                    reply.Header("Connection").Equals("close", StringComparison.OrdinalIgnoreCase) &&
                    !reply.Body.Contains("HTTP/1.1", StringComparison.Ordinal),
                $"Ambiguous framing must be rejected with connection close and no appended response: {headers}", reply.Headers + "\n" + reply.Body);
        }

        foreach (var framing in new[]
        {
            "Content-Length: 4\r\n\r\ntest",
            "Transfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n"
        })
        {
            var reply = await Raw($"POST /ca/csr HTTP/1.1\r\nHost: {Host}:{Port}\r\nConnection: close\r\n{framing}")
                .ConfigureAwait(false);
            Observe(reply.Status is 401 or 403, "Valid framing must reach the authentication boundary", reply.Headers);
        }
    }

    private async Task RejectedPaths()
    {
        foreach (var path in new[] { "/wp-login.php", "/cgi-bin/pentest", "/xmlrpc.php", "/.git/config", "/appsettings.json" })
        {
            var reply = await Request(path).ConfigureAwait(false);
            Observe(reply.Status is 403 or 404, $"Scanner path {path} must not expose files or application content", reply.Headers);
        }
    }

    private async Task HeaderLimit()
    {
        var reply = await Raw($"GET /health HTTP/1.1\r\nHost: {Host}:{Port}\r\nX-Pentest: {new string('a', 65536)}"
            + "\r\nConnection: close\r\n\r\n").ConfigureAwait(false);
        Observe(reply.Status is 400 or 431, "Oversized request headers must be rejected", reply.Headers);
    }

    private async Task<Reply> Raw(string request)
    {
        var script = File.ReadAllText(Path.Combine(RepositoryPaths.IqProject, "client", "scripts", "pentest-raw-request.py"));
        var result = await Tool("python3", "-c", script, Host, Port.ToString(CultureInfo.InvariantCulture),
            TrustRoot, Convert.ToBase64String(Encoding.ASCII.GetBytes(request))).ConfigureAwait(false);
        Assert.True(result.ExitCode == 0, $"Raw TLS probe failed:\n{result.Stdout}\n{result.Stderr}");
        return Reply.Parse(result.Stdout);
    }

    private sealed record Reply(int Status, string Headers, string Body)
    {
        public string Header(string name) => Headers.Split("\r\n")
            .FirstOrDefault(line => line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
            ?[(name.Length + 1)..]?.Trim() ?? "";

        public static Reply Parse(string text)
        {
            var split = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (split < 0 || !text.StartsWith("HTTP/1.1 ", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"No complete HTTP/1.1 response received:\n{text}");
            }

            return new Reply(int.Parse(text.Split(' ', 3)[1], CultureInfo.InvariantCulture),
                text[..split], text[(split + 4)..]);
        }
    }
}
