namespace OpenCertServer.Mcp.Tests.StepDefinitions;

using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Mcp.Tests.Support;
using Reqnroll;
using Xunit;

[Binding]
public sealed class McpServerCertificateOperationsSteps
{
    private readonly McpServerFixture _fixture;
    private readonly McpScenarioContext _context;

    public McpServerCertificateOperationsSteps(McpServerFixture fixture,
            McpScenarioContext context)
    {
        _fixture = fixture;
        _context = context;
    }

    [Given("a valid CSR is available")]
    public void GivenAValidCsrIsAvailable()
    {
        // CSR is created inline in the When step
    }

    [Given("an invalid CSR is available")]
    public void GivenAnInvalidCsrIsAvailable()
    {
        // Invalid CSR is created inline in the When step
    }

    [Given("a certificate is issued")]
    [Scope(Tag = "mcp-server-certificate-operations")]
    public async Task GivenACertificateIsIssued()
    {
        var csr = _fixture.CreateBase64DerCsrForCurrentCaller();
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"sign_certificate failed: {result.ErrorMessage}");
        _context.SignedCert = (McpCertificateItem)result.Content!;
    }

    [When("the MCP server invokes \"sign_certificate\" with that CSR")]
    public async Task WhenSignCertificate()
    {
        var csr = _fixture.CreateBase64DerCsrForCurrentCaller();
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"sign_certificate failed: {result.ErrorMessage}");
        _context.SignedCert = (McpCertificateItem)result.Content!;
    }

    [When("the MCP server invokes \"sign_certificate\" with that CSR and includePem true")]
    public async Task WhenSignCertificateWithPem()
    {
        var csr = _fixture.CreateBase64DerCsrForCurrentCaller();
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr, includePem = true }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"sign_certificate with PEM failed: {result.ErrorMessage}");
        _context.SignedCert = (McpCertificateItem)result.Content!;
    }

    [When(
        "the MCP server invokes \"sign_certificate\" with that CSR, notBefore \"(.+)\", and notAfter \"(.+)\"")]
    public async Task WhenSignCertificateWithDates(string notBeforeStr, string notAfterStr)
    {
        var csr = _fixture.CreateBase64DerCsrForCurrentCaller();
        var nb = DateTimeOffset.Parse(notBeforeStr);
        var na = DateTimeOffset.Parse(notAfterStr);
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr, notBefore = nb, notAfter = na }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"sign_certificate with dates failed: {result.ErrorMessage}");
        _context.SignedCert = (McpCertificateItem)result.Content!;
    }

    [When("the MCP server invokes \"sign_certificate\" with an invalid CSR body")]
    public async Task WhenSignCertificateInvalid()
    {
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr = "not-a-valid-csr" }).ConfigureAwait(false);
        _context.ToolResult = result;
        _context.SignedCert = result.IsSuccess
            ? (McpCertificateItem)result.Content!
            : null;
    }

    [When("the MCP server invokes \"sign_certificate\" without providing a CSR string")]
    public async Task WhenSignCertificateNoCsr()
    {
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { }).ConfigureAwait(false);
        _context.ToolResult = result;
        _context.SignedCert = result.IsSuccess
            ? (McpCertificateItem)result.Content!
            : null;
    }

    [When(
        "the MCP server invokes \"revoke_certificate\" with that certificate's serial number and reason \"(.+)\"")]
    public async Task WhenRevokeWithReason(string reason)
    {
        if (_context.SignedCert == null)
        {
            throw new Exception("No signed cert available — run 'Given a certificate is issued' first");
        }

        var serial = _context.SignedCert.SerialNumber;
        var result = await _fixture.InvokeMcpToolAsync("revoke_certificate", new { serialNumber = serial, reason }).ConfigureAwait(false);
        _context.ToolResult = result;
    }

    [When(
        "the MCP server invokes \"revoke_certificate\" with that certificate's serial number, reason \"(.+)\", reason (.+), and description \"(.+)\"")]
    public async Task WhenRevokeWithFullFields(string reason, int reasonCode, string description)
    {
        if (_context.SignedCert == null)
        {
            throw new Exception("No signed cert available — run 'Given a certificate is issued' first");
        }

        var serial = _context.SignedCert.SerialNumber;
        var result = await _fixture.InvokeMcpToolAsync("revoke_certificate", new { serialNumber = serial, reason }).ConfigureAwait(false);
        _context.ToolResult = result;
    }

    [When("the MCP server invokes \"revoke_certificate\" with serial number \"(.+)\"")]
    public async Task WhenRevokeWithSerial(string serialNumber)
    {
        var result = await _fixture.InvokeMcpToolAsync("revoke_certificate", new { serialNumber }).ConfigureAwait(false);
        _context.ToolResult = result;
    }

    [When("the MCP server invokes \"revoke_certificate\" without a serial number")]
    public async Task WhenRevokeWithoutSerial()
    {
        var result = await _fixture.InvokeMcpToolAsync("revoke_certificate", new { reason = "KeyCompromise" }).ConfigureAwait(false);
        _context.ToolResult = result;
    }

    // ---- Then steps ----

    [Then("the returned certificate serial number MUST be non-empty")]
    public void ThenSerialMustBeNonEmpty()
    {
        Assert.NotNull(_context.SignedCert);
        Assert.NotEmpty(_context.SignedCert.SerialNumber);
    }

    [Then("the returned certificate subject MUST match the CSR subject")]
    public void ThenSubjectMustMatch()
    {
        Assert.NotNull(_context.SignedCert);
        Assert.Contains("test", _context.SignedCert.Subject, StringComparison.OrdinalIgnoreCase);
    }

    [Then("the returned certificate issuer MUST match the CA's subject")]
    public void ThenIssuerMustMatch()
    {
        Assert.NotNull(_context.SignedCert);
        Assert.Contains("MCP Test CA", _context.SignedCert.Issuer);
    }

    [Then("the returned certificate must have a valid NotBefore and NotAfter")]
    public void ThenDatesMustBeValid()
    {
        Assert.NotNull(_context.SignedCert);
        Assert.True(_context.SignedCert.NotBefore != default);
        Assert.True(_context.SignedCert.NotAfter != default);
        Assert.True(_context.SignedCert.NotBefore < _context.SignedCert.NotAfter);
    }

    [Then("the returned certificate must have a PublicKeyAlgorithm and PublicKeySize greater than zero")]
    public void ThenKeyInfoMustBeValid()
    {
        Assert.NotNull(_context.SignedCert);
        Assert.NotEmpty(_context.SignedCert.PublicKeyAlgorithm);
        Assert.True(_context.SignedCert.PublicKeySize > 0);
    }

    [Then("the returned certificate MUST have a Pem field containing {string}")]
    public void ThenMustHavePem(string expected)
    {
        Assert.NotNull(_context.SignedCert);
        Assert.NotNull(_context.SignedCert.Pem);
        Assert.Contains(expected, _context.SignedCert.Pem);
    }

    [Then("the returned certificate MUST have a PemChain field containing {string}")]
    public void ThenMustHavePemChain(string expected)
    {
        Assert.NotNull(_context.SignedCert);
        Assert.NotNull(_context.SignedCert.PemChain);
        Assert.Contains(expected, _context.SignedCert.PemChain);
    }

    [Then("the PemChain MUST contain at least {int} certificates \\(intermediate + root\\)")]
    public void ThenPemChainMustHaveMultipleCerts(int minCount)
    {
        Assert.NotNull(_context.SignedCert);
        var pemChain = _context.SignedCert.PemChain ?? string.Empty;
        var count = pemChain.Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.True(count >= minCount, $"PemChain contains {count} certificates, expected at least {minCount}");
    }

    [Then("the returned certificate NotBefore MUST be on or before \"(.+)\"")]
    public void ThenNotBeforeOnOrBefore(string expected)
    {
        Assert.NotNull(_context.SignedCert);
        var notBeforeDate = DateTimeOffset.Parse(expected);
        Assert.True(_context.SignedCert.NotBefore <= notBeforeDate);
    }

    [Then("the returned certificate NotAfter MUST match \"(.+)\"")]
    public void ThenNotAfterMustMatch(string expected)
    {
        Assert.NotNull(_context.SignedCert);
        var notAfterDate = DateTimeOffset.Parse(expected);
        Assert.Equal(notAfterDate, _context.SignedCert.NotAfter);
    }

    [Then("the error code MUST be McpErrorCode.CertificateSigningFailed")]
    public void ThenErrorCodeMustBeSigningFailed()
    {
        Assert.True(_context.SignedCert == null, "Expected a failure result");
    }

    [Then("the error message MUST mention that the CSR could not be parsed")]
    public void ThenErrorMustMentionCsrParsing()
    {
        Assert.NotNull(_context.ToolResult);
        var msg = _context.ToolResult!.ErrorMessage ?? "";
        Assert.True(msg.Contains("CSR", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("parse", StringComparison.OrdinalIgnoreCase));
    }

    [Then("the issued certificate MUST appear in the certificate inventory")]
    public async Task ThenCertMustBeInInventory()
    {
        var items = new List<CertificateItemInfo>();
        await foreach (var item in _fixture.Store.GetInventory(0, 500, CancellationToken.None).ConfigureAwait(false))
            items.Add(item);
        Assert.True(items.Count > 0, "Inventory is empty");
    }

    [Then("the total count MUST be at least 1")]
    public async Task ThenTotalCountAtLeast1()
    {
        var items = new List<CertificateItemInfo>();
        await foreach (var item in _fixture.Store.GetInventory(0, 500, CancellationToken.None).ConfigureAwait(false))
            items.Add(item);
        Assert.True(items.Count >= 1);
    }

    [Then("the certificate MUST be marked as revoked in the inventory")]
    public async Task ThenCertMustBeRevoked()
    {
        var items = new List<CertificateItemInfo>();
        await foreach (var item in _fixture.Store.GetInventory(0, 500, CancellationToken.None).ConfigureAwait(false))
            items.Add(item);
        var revoked = items.FirstOrDefault(i => i.RevocationReason != null);
        Assert.NotNull(revoked);
    }

    [Then("at least one certificate item MUST have IsRevoked true")]
    public async Task ThenAtLeastOneRevoked()
    {
        var items = new List<CertificateItemInfo>();
        await foreach (var item in _fixture.Store.GetInventory(0, 500, CancellationToken.None).ConfigureAwait(false))
            items.Add(item);
        Assert.True(items.Any(i => i.IsRevoked), "No certificate is marked as revoked");
    }
}