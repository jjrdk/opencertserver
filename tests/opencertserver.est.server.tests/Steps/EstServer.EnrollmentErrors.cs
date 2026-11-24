namespace OpenCertServer.Est.Tests.Steps;

using System.Net;
using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils.Ca;
using Reqnroll;
using Xunit;

public partial class EstServer
{
    private const string InternalFailure = "private database host:5432";

    [Given("an EST validator that fails with {string} during signing")]
    public void ConfigureFailingValidator(string failure)
    {
        _context["failureValidator"] = new FailingValidator(failure);
        _context["failureLogger"] = new FailureLogProvider();
    }

    [When("a client submits a {string} CSR to {string}")]
    public async Task SubmitMalformedCsr(string kind, string endpoint)
    {
        using var key = RSA.Create(2048);
        using var certificate = await GetCertificate(key).ConfigureAwait(false);
        var request = new CertificateRequest(certificate.SubjectName, key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        if (kind == "malformed keyusage")
        {
            request.CertificateExtensions.Add(new X509Extension("2.5.29.15", [0x03, 0x02, 0xff], true));
        }
        else if (kind == "malformed SAN")
        {
            request.CertificateExtensions.Add(new X509Extension("2.5.29.17", [0x04, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x00], false));
        }
        else if (kind == "malformed otherName")
        {
            request.CertificateExtensions.Add(new X509Extension("2.5.29.17", [0x30, 0x02, 0xa0, 0x00], false));
        }

        var der = request.CreateSigningRequest();
        if (kind == "invalid signature")
        {
            der[^1] ^= 1;
        }

        var body = kind switch
        {
            "invalid base64" => "not base64!",
            "invalid DER" => Convert.ToBase64String([0x30, 0x01, 0xff]),
            "unsupported key" => "MIGVMEkCAQAwFjEUMBIGA1UEAwwLdW5zdXBwb3J0ZWQwKjAFBgMrZXADIQDux/fNuBvbt+Q9Eq2jBdX4jbH8okK8TcJaC9/s4peCAaAAMAUGAytlcANBAGajC/eHku6iTHuj3KeYciSsCkQ+GrmxCs7Hdtew8L56DJbI26aRgxi+F66RvqSxaV/Lwy0zb+cA6PSyNvrdRAs=",
            _ => Convert.ToBase64String(der)
        };
        if (_context.TryGetValue("failureValidator", out var validator))
        {
            ((FailingValidator)validator).Enabled = true;
        }
        using var client = new HttpClient(new TestMessageHandler(_server, certificate));
        using var response = await client.PostAsync(
            $"https://localhost/.well-known/est/rsa/{endpoint}",
            new StringContent(body, Encoding.UTF8, "application/pkcs10")).ConfigureAwait(false);
        _context["estErrorStatus"] = response.StatusCode;
        _context["estErrorBody"] = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    }

    [Then("the EST response is {int} with {string}")]
    public void AssertEstError(int status, string message)
    {
        Assert.Equal((HttpStatusCode)status, (HttpStatusCode)_context["estErrorStatus"]);
        Assert.Equal(message, (string)_context["estErrorBody"]);
    }

    [Then("the EST response status is {int}")]
    public void AssertEstStatus(int status) =>
        Assert.Equal((HttpStatusCode)status, (HttpStatusCode)_context["estErrorStatus"]);

    [Then("the internal failure is logged")]
    public void AssertInternalFailureLogged()
    {
        var logger = (FailureLogProvider)_context["failureLogger"];
        Assert.Contains(logger.Exceptions, exception => exception.Message == InternalFailure);
        Assert.DoesNotContain(InternalFailure, (string)_context["estErrorBody"]);
    }

    private sealed class FailingValidator(string failure) : IValidateCertificateRequests<PreIssuingContext>
    {
        public bool Enabled { get; set; }

        public Task<ValidationResult> Validate(PreIssuingContext context, CancellationToken cancellationToken = default)
        {
            if (Enabled)
            {
                throw failure == "cryptographic"
                    ? new CryptographicException(InternalFailure)
                    : new InvalidOperationException(InternalFailure);
            }

            return Task.FromResult(ValidationResult.Passed);
        }
    }

    private sealed class FailureLogProvider : ILoggerProvider
    {
        public ConcurrentQueue<Exception> Exceptions { get; } = new();
        public ILogger CreateLogger(string categoryName) => new FailureLogger(Exceptions);
        public void Dispose() { }
    }

    private sealed class FailureLogger(ConcurrentQueue<Exception> exceptions) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (exception != null)
            {
                exceptions.Enqueue(exception);
            }
        }
    }
}
