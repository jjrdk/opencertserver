namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Diagnostics;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private string? _openSslOutput;

    [When("OpenSSL sends an OCSP request with a nonce for an issued certificate")]
    public async Task WhenOpenSslSendsAnOcspRequestWithANonceForAnIssuedCertificate()
    {
        Assert.SkipUnless(OpenSslAvailable(), "openssl is not installed.");
        var issuer = await GetIssuerCertAsync().ConfigureAwait(false);
        var leaf = await GetOrEnrollLeafCertAsync().ConfigureAwait(false);

        var dir = Directory.CreateTempSubdirectory("ocsp-interop-").FullName;
        try
        {
            var issuerPem = Path.Combine(dir, "issuer.pem");
            var leafPem = Path.Combine(dir, "leaf.pem");
            var requestFile = Path.Combine(dir, "request.der");
            var responseFile = Path.Combine(dir, "response.der");
            await File.WriteAllTextAsync(issuerPem, issuer.ExportCertificatePem()).ConfigureAwait(false);
            await File.WriteAllTextAsync(leafPem, leaf.ExportCertificatePem()).ConfigureAwait(false);

            // OpenSSL's defaults: SHA-1 CertID and a nonce extension, as most clients send them.
            await RunOpenSsl("ocsp", "-issuer", issuerPem, "-cert", leafPem, "-reqout", requestFile)
                .ConfigureAwait(false);

            var (_, http) = await SendRawOcspPostAsync(await File.ReadAllBytesAsync(requestFile).ConfigureAwait(false))
                .ConfigureAwait(false);
            await File.WriteAllBytesAsync(responseFile, await http.Content.ReadAsByteArrayAsync().ConfigureAwait(false))
                .ConfigureAwait(false);

            // -reqin makes OpenSSL compare the nonce with the request's, -CAfile makes it verify the
            // signature, -resp_text prints the status. No -issuer/-cert here: with them OpenSSL
            // builds a request of its own, with a fresh nonce, and compares against that.
            _openSslOutput = await RunOpenSsl(
                    "ocsp", "-reqin", requestFile, "-respin", responseFile, "-CAfile", issuerPem, "-resp_text")
                .ConfigureAwait(false);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Then("OpenSSL verifies the response signature against the CA certificate")]
    public void ThenOpenSslVerifiesTheResponseSignatureAgainstTheCaCertificate()
    {
        Assert.Contains("Response verify OK", _openSslOutput);
    }

    [Then("OpenSSL reports the certificate as good")]
    public void ThenOpenSslReportsTheCertificateAsGood()
    {
        Assert.Contains("Cert Status: good", _openSslOutput);
    }

    [Then("OpenSSL reports the certificate as revoked for key compromise")]
    public void ThenOpenSslReportsTheCertificateAsRevokedForKeyCompromise()
    {
        Assert.Contains("Cert Status: revoked", _openSslOutput);
        Assert.Contains("Revocation Reason: keyCompromise", _openSslOutput);
    }

    [Then("OpenSSL finds its nonce in the response")]
    public void ThenOpenSslFindsItsNonceInTheResponse()
    {
        Assert.DoesNotContain("WARNING: no nonce in response", _openSslOutput);
        Assert.DoesNotContain("Nonce Verify error", _openSslOutput);
    }

    private static bool OpenSslAvailable()
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("openssl", "version")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            process?.WaitForExit();
            return process is { ExitCode: 0 };
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static async Task<string> RunOpenSsl(params string[] arguments)
    {
        var start = new ProcessStartInfo("openssl")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().ConfigureAwait(false);
        var text = await output.ConfigureAwait(false) + await error.ConfigureAwait(false);
        Assert.True(process.ExitCode == 0, $"openssl {string.Join(' ', arguments)} failed:\n{text}");
        return text;
    }
}
