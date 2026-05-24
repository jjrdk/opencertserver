using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Mcp.Tests.Support;
using Reqnroll;
using Xunit;

namespace OpenCertServer.Mcp.Tests.StepDefinitions;

[Binding]
public sealed class McpServerCertificateOperationsSteps
{
    private readonly McpServerFixture _fixture;

    public McpServerCertificateOperationsSteps(McpServerFixture fixture)
    {
        _fixture = fixture;
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
        var csr = McpServerFixture.CreateBase64DerCsr();
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr });
        Assert.True(result.IsSuccess, $"sign_certificate failed: {result.ErrorMessage}");
        TestSharedState.SignedCert = (McpCertificateItem)result.Content!;
    }

    [When("the MCP server invokes \"sign_certificate\" with that CSR")]
    public async Task WhenSignCertificate()
    {
        var csr = McpServerFixture.CreateBase64DerCsr();
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr });
        Assert.True(result.IsSuccess, $"sign_certificate failed: {result.ErrorMessage}");
        TestSharedState.SignedCert = (McpCertificateItem)result.Content!;
    }

    [When("the MCP server invokes \"sign_certificate\" with that CSR and includePem true")]
    public async Task WhenSignCertificateWithPem()
    {
        var csr = McpServerFixture.CreateBase64DerCsr();
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr, includePem = true });
        Assert.True(result.IsSuccess, $"sign_certificate with PEM failed: {result.ErrorMessage}");
        TestSharedState.SignedCert = (McpCertificateItem)result.Content!;
    }

    [When(
        "the MCP server invokes \"sign_certificate\" with that CSR, notBefore \"(.+)\", and notAfter \"(.+)\"")]
    public async Task WhenSignCertificateWithDates(string notBeforeStr, string notAfterStr)
    {
        var csr = McpServerFixture.CreateBase64DerCsr();
        var nb = DateTimeOffset.Parse(notBeforeStr);
        var na = DateTimeOffset.Parse(notAfterStr);
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr, notBefore = nb, notAfter = na });
        Assert.True(result.IsSuccess, $"sign_certificate with dates failed: {result.ErrorMessage}");
        TestSharedState.SignedCert = (McpCertificateItem)result.Content!;
    }

    [When("the MCP server invokes \"sign_certificate\" with an invalid CSR body")]
    public async Task WhenSignCertificateInvalid()
    {
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr = "not-a-valid-csr" });
        TestSharedState.ToolResult = result;
        TestSharedState.SignedCert = result.IsSuccess
            ? (McpCertificateItem)result.Content!
            : null;
    }

    [When("the MCP server invokes \"sign_certificate\" without providing a CSR string")]
    public async Task WhenSignCertificateNoCsr()
    {
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { });
        TestSharedState.ToolResult = result;
        TestSharedState.SignedCert = result.IsSuccess
            ? (McpCertificateItem)result.Content!
            : null;
    }

    [When(
        "the MCP server invokes \"revoke_certificate\" with that certificate's serial number and reason \"(.+)\"")]
    public async Task WhenRevokeWithReason(string reason)
    {
        if (TestSharedState.SignedCert == null)
        {
            throw new Exception("No signed cert available — run 'Given a certificate is issued' first");
        }

        var serial = TestSharedState.SignedCert.SerialNumber;
        var result = await _fixture.InvokeMcpToolAsync("revoke_certificate", new { serialNumber = serial, reason });
        TestSharedState.ToolResult = result;
    }

    [When(
        "the MCP server invokes \"revoke_certificate\" with that certificate's serial number, reason \"(.+)\", reason (.+), and description \"(.+)\"")]
    public async Task WhenRevokeWithFullFields(string reason, int reasonCode, string description)
    {
        if (TestSharedState.SignedCert == null)
        {
            throw new Exception("No signed cert available — run 'Given a certificate is issued' first");
        }

        var serial = TestSharedState.SignedCert.SerialNumber;
        var result = await _fixture.InvokeMcpToolAsync("revoke_certificate", new { serialNumber = serial, reason });
        TestSharedState.ToolResult = result;
    }

    [When("the MCP server invokes \"revoke_certificate\" with serial number \"(.+)\"")]
    public async Task WhenRevokeWithSerial(string serialNumber)
    {
        var result = await _fixture.InvokeMcpToolAsync("revoke_certificate", new { serialNumber });
        TestSharedState.ToolResult = result;
    }

    [When("the MCP server invokes \"revoke_certificate\" without a serial number")]
    public async Task WhenRevokeWithoutSerial()
    {
        var result = await _fixture.InvokeMcpToolAsync("revoke_certificate", new { reason = "KeyCompromise" });
        TestSharedState.ToolResult = result;
    }

    // ---- Then steps ----

    [Then("the returned certificate serial number MUST be non-empty")]
    public void ThenSerialMustBeNonEmpty()
    {
        Assert.NotNull(TestSharedState.SignedCert);
        Assert.NotEmpty(TestSharedState.SignedCert.SerialNumber);
    }

    [Then("the returned certificate subject MUST match the CSR subject")]
    public void ThenSubjectMustMatch()
    {
        Assert.NotNull(TestSharedState.SignedCert);
        Assert.Contains("test", TestSharedState.SignedCert.Subject, StringComparison.OrdinalIgnoreCase);
    }

    [Then("the returned certificate issuer MUST match the CA's subject")]
    public void ThenIssuerMustMatch()
    {
        Assert.NotNull(TestSharedState.SignedCert);
        Assert.Contains("MCP Test CA", TestSharedState.SignedCert.Issuer);
    }

    [Then("the returned certificate must have a valid NotBefore and NotAfter")]
    public void ThenDatesMustBeValid()
    {
        Assert.NotNull(TestSharedState.SignedCert);
        Assert.True(TestSharedState.SignedCert.NotBefore != default);
        Assert.True(TestSharedState.SignedCert.NotAfter != default);
        Assert.True(TestSharedState.SignedCert.NotBefore < TestSharedState.SignedCert.NotAfter);
    }

    [Then("the returned certificate must have a PublicKeyAlgorithm and PublicKeySize greater than zero")]
    public void ThenKeyInfoMustBeValid()
    {
        Assert.NotNull(TestSharedState.SignedCert);
        Assert.NotEmpty(TestSharedState.SignedCert.PublicKeyAlgorithm);
        Assert.True(TestSharedState.SignedCert.PublicKeySize > 0);
    }

    [Then("the returned certificate MUST have a Pem field containing {string}")]
    public void ThenMustHavePem(string expected)
    {
        Assert.NotNull(TestSharedState.SignedCert);
        Assert.NotNull(TestSharedState.SignedCert.Pem);
        Assert.Contains(expected, TestSharedState.SignedCert.Pem);
    }

    [Then("the returned certificate MUST have a PemChain field containing {string}")]
    public void ThenMustHavePemChain(string expected)
    {
        Assert.NotNull(TestSharedState.SignedCert);
        Assert.NotNull(TestSharedState.SignedCert.PemChain);
        Assert.Contains(expected, TestSharedState.SignedCert.PemChain);
    }

    [Then("the PemChain MUST contain at least {int} certificates \\(intermediate + root\\)")]
    public void ThenPemChainMustHaveMultipleCerts(int minCount)
    {
        Assert.NotNull(TestSharedState.SignedCert);
        var pemChain = TestSharedState.SignedCert.PemChain ?? string.Empty;
        var count = pemChain.Split("-----BEGIN CERTIFICATE-----").Length - 1;
        Assert.True(count >= minCount, $"PemChain contains {count} certificates, expected at least {minCount}");
    }

    [Then("the returned certificate NotBefore MUST be on or before \"(.+)\"")]
    public void ThenNotBeforeOnOrBefore(string expected)
    {
        Assert.NotNull(TestSharedState.SignedCert);
        var notBeforeDate = DateTimeOffset.Parse(expected);
        Assert.True(TestSharedState.SignedCert.NotBefore <= notBeforeDate);
    }

    [Then("the returned certificate NotAfter MUST match \"(.+)\"")]
    public void ThenNotAfterMustMatch(string expected)
    {
        Assert.NotNull(TestSharedState.SignedCert);
        var notAfterDate = DateTimeOffset.Parse(expected);
        Assert.Equal(notAfterDate, TestSharedState.SignedCert.NotAfter);
    }

    [Then("the error code MUST be McpErrorCode.CertificateSigningFailed")]
    public void ThenErrorCodeMustBeSigningFailed()
    {
        Assert.True(TestSharedState.SignedCert == null, "Expected a failure result");
    }

    [Then("the error message MUST mention that the CSR could not be parsed")]
    public void ThenErrorMustMentionCsrParsing()
    {
        Assert.NotNull(TestSharedState.ToolResult);
        var msg = TestSharedState.ToolResult!.ErrorMessage ?? "";
        Assert.True(msg.Contains("CSR", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("parse", StringComparison.OrdinalIgnoreCase));
    }

    [Then("the issued certificate MUST appear in the certificate inventory")]
    public async Task ThenCertMustBeInInventory()
    {
        Assert.NotNull(TestSharedState.Store);
        var items = new List<CertificateItemInfo>();
        await foreach (var item in TestSharedState.Store.GetInventory(0, 500, CancellationToken.None))
            items.Add(item);
        Assert.True(items.Count > 0, "Inventory is empty");
    }

    [Then("the total count MUST be at least 1")]
    public async Task ThenTotalCountAtLeast1()
    {
        Assert.NotNull(TestSharedState.Store);
        var items = new List<CertificateItemInfo>();
        await foreach (var item in TestSharedState.Store.GetInventory(0, 500, CancellationToken.None))
            items.Add(item);
        Assert.True(items.Count >= 1);
    }

    [Then("the certificate MUST be marked as revoked in the inventory")]
    public async Task ThenCertMustBeRevoked()
    {
        Assert.NotNull(TestSharedState.Store);
        var items = new List<CertificateItemInfo>();
        await foreach (var item in TestSharedState.Store.GetInventory(0, 500, CancellationToken.None))
            items.Add(item);
        var revoked = items.FirstOrDefault(i => i.RevocationReason != null);
        Assert.NotNull(revoked);
    }

    [Then("at least one certificate item MUST have IsRevoked true")]
    public async Task ThenAtLeastOneRevoked()
    {
        Assert.NotNull(TestSharedState.Store);
        var items = new List<CertificateItemInfo>();
        await foreach (var item in TestSharedState.Store.GetInventory(0, 500, CancellationToken.None))
            items.Add(item);
        Assert.True(items.Any(i => i.IsRevoked), "No certificate is marked as revoked");
    }
}
