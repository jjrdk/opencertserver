namespace OpenCertServer.Mcp.Tests.StepDefinitions;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Mcp.Tests.Support;
using OpenCertServer.Mcp.Tools;
using Reqnroll;
using Xunit;

[Binding]
public sealed class McpServerRevocationSteps
{
    private readonly McpServerFixture _fixture;
    private readonly McpScenarioContext _context;
    private readonly List<X509Certificate2> _issuedCerts = new();

    public McpServerRevocationSteps(McpServerFixture fixture,
            McpScenarioContext context)
    {
        _fixture = fixture;
        _context = context;
    }

    private McpRevocationStatusResult RequireRevocationStatusResult()
    {
        if (_context.RevocationStatusResult == null &&
            _context.ToolResult?.Content is McpRevocationStatusResult fromToolResult)
        {
            _context.RevocationStatusResult = fromToolResult;
        }

        return _context.RevocationStatusResult
            ?? throw new Exception("No revocation status result available in shared state");
    }

    private async Task<(string serial, string nameHash, string keyHash)> GetCertInfoAsync()
    {
        if (_issuedCerts.Count == 0)
        {
            throw new InvalidOperationException("No certificates issued yet");
        }

        var cert = _issuedCerts[^1];

        var nameHashBytes = SHA256.Create()!.ComputeHash(cert.SubjectName.RawData);
        var keyBytes = cert.GetPublicKey()!;

        return (cert.GetSerialNumberString(),
                Convert.ToHexString(nameHashBytes),
                Convert.ToHexString(keyBytes));
    }

    [Given("a certificate is issued")]
    [Scope(Tag = "mcp-server-revocation")]
    public async Task GivenACertificateIsIssued()
    {
        // This issues a cert that goes into the scenario context; also stash in _issuedCerts for OCSP
        var csr = McpServerFixture.CreateBase64DerCsr();
        var mcpResult = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr }).ConfigureAwait(false);
        if (mcpResult.IsSuccess)
        {
            _context.SignedCert = (McpCertificateItem)mcpResult.Content!;
        }

        // Also need an actual X509Certificate2 in _issuedCerts for hash computation
        var cert = await _fixture.CreateAndIssueCertificateAsync("test-rev-check-1").ConfigureAwait(false);
        _issuedCerts.Add(cert);
    }

    [Given("another certificate is issued and then revoked")]
    public async Task GivenAnotherCertificateIssuedAndRevoked()
    {
        // Issue second cert
        var cert = await _fixture.CreateAndIssueCertificateAsync("test-rev-check-2").ConfigureAwait(false);
        _issuedCerts.Add(cert);

        // Also add to shared state so common assertions work
        var csr = McpServerFixture.CreateBase64DerCsr();
        var mcpResult = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr }).ConfigureAwait(false);
        if (mcpResult.IsSuccess)
        {
            _context.SignedCert = (McpCertificateItem)mcpResult.Content!;
        }

        // Revoke it via MCP
        await _fixture.InvokeMcpToolAsync("revoke_certificate", new
        {
            serialNumber = cert.GetSerialNumberString(),
            reason = "KeyCompromise"
        }).ConfigureAwait(false);
    }

    [When("the MCP server invokes \"get_crl\" with default parameters")]
    public async Task WhenGetCrlDefault()
    {
        var result = await _fixture.InvokeMcpToolAsync("get_crl", new { }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"get_crl failed: {result.ErrorMessage}");
        _context.ToolResult = result;
        _context.CrlResult = (McpCrlResult)result.Content!;
    }

    [When("the MCP server invokes \"get_crl\" with profileName \"(.+)\"")]
    public async Task WhenGetCrlWithProfile(string profileName)
    {
        var result = await _fixture.InvokeMcpToolAsync("get_crl", new { profileName }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"get_crl with profile failed: {result.ErrorMessage}");
        _context.ToolResult = result;
        _context.CrlResult = (McpCrlResult)result.Content!;
    }

    [When("the MCP server invokes \"get_crl\" with includePem true")]
    public async Task WhenGetCrlWithPem()
    {
        var result = await _fixture.InvokeMcpToolAsync("get_crl", new { includePem = true }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"get_crl with PEM failed: {result.ErrorMessage}");
        _context.ToolResult = result;
        _context.CrlResult = (McpCrlResult)result.Content!;
    }

    [When(
            "the MCP server invokes \"check_ocsp_status\" with the certificate's serial number, issuer name hash, and issuer key hash")]
    public async Task WhenCheckOcspWithGoodCert()
    {
        var (serial, nameHash, keyHash) = await GetCertInfoAsync().ConfigureAwait(false);
        var result = await _fixture.InvokeMcpToolAsync("check_ocsp_status", new
        {
            serialNumber = serial,
            issuerNameHash = nameHash,
            issuerKeyHash = keyHash
        }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"check_ocsp_status failed: {result.ErrorMessage}");
        _context.OcspResult = (McpOcspCheckResult)result.Content!;
        _context.ToolResult = result;
    }

    [When(
            "the MCP server invokes \"check_ocsp_status\" with serial number \"(.+)\", issuer name hash \"(.+)\", and issuer key hash \"(.+)\"")]
    public async Task WhenCheckOcspWithSerial(string serial, string nameHash, string keyHash)
    {
        var result = await _fixture.InvokeMcpToolAsync("check_ocsp_status", new
        {
            serialNumber = serial,
            issuerNameHash = nameHash,
            issuerKeyHash = keyHash
        }).ConfigureAwait(false);
        _context.OcspResult = result.IsSuccess
                ? (McpOcspCheckResult)result.Content!
                : null;
        _context.ToolResult = result;
    }

    [When("the MCP server invokes \"check_ocsp_status\" with serial number \"(.+)\" but no issuer hashes")]
    public async Task WhenCheckOcspWithoutHashes(string serial)
    {
        var result = await _fixture.InvokeMcpToolAsync("check_ocsp_status", new { serialNumber = serial }).ConfigureAwait(false);
        _context.OcspResult = result.IsSuccess
                ? (McpOcspCheckResult)result.Content!
                : null;
        _context.ToolResult = result;
    }

    [When(
            "the MCP server invokes \"get_revocation_status\" with an array containing the certificate's serial number")]
    public async Task WhenGetRevStatusWithGoodCert()
    {
        var (serial, _, _) = await GetCertInfoAsync().ConfigureAwait(false);
        _context.RequestedSerialNumber = serial;
        var result = await _fixture.InvokeMcpToolAsync("get_revocation_status", new
        {
            serialNumbers = new[] { serial }
        }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"get_revocation_status failed: {result.ErrorMessage}");
        _context.RevocationStatusResult = (McpRevocationStatusResult)result.Content!;
        _context.ToolResult = result;
    }

    [When("the MCP server invokes \"get_revocation_status\" with serial number \"(.+)\"")]
    public async Task WhenGetRevStatusWithUnknownCert(string serial)
    {
        _context.RequestedSerialNumber = serial;
        var result = await _fixture.InvokeMcpToolAsync("get_revocation_status", new
        {
            serialNumbers = new[] { serial }
        }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"get_revocation_status failed: {result.ErrorMessage}");
        _context.RevocationStatusResult = (McpRevocationStatusResult)result.Content!;
        _context.ToolResult = result;
    }

    [When("the MCP server invokes \"get_revocation_status\" with an empty serialNumbers array")]
    public async Task WhenGetRevStatusWithEmptyArray()
    {
        var result = await _fixture.InvokeMcpToolAsync("get_revocation_status", new
        {
            serialNumbers = Array.Empty<string>()
        }).ConfigureAwait(false);
        _context.ToolResult = result;
    }

    [When("the MCP server invokes \"get_revocation_status\" with both certificates' serial numbers")]
    public async Task WhenGetRevStatusWithMixedCerts()
    {
        var serials = _issuedCerts.Select(c => c.GetSerialNumberString()).ToList();
        var result = await _fixture.InvokeMcpToolAsync("get_revocation_status", new
        {
            serialNumbers = serials
        }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"get_revocation_status failed: {result.ErrorMessage}");
        _context.RevocationStatusResult = (McpRevocationStatusResult)result.Content!;
        _context.ToolResult = result;
    }

    [When("the MCP server invokes \"get_revocation_status\" with serial numbers and profileName \"(.+)\"")]
    public async Task WhenGetRevStatusWithProfile(string profileName)
    {
        var serials = _issuedCerts.Select(c => c.GetSerialNumberString()).ToList();
        var result = await _fixture.InvokeMcpToolAsync("get_revocation_status", new
        {
            serialNumbers = serials,
            profileName = profileName
        }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"get_revocation_status with profile failed: {result.ErrorMessage}");
        _context.RevocationStatusResult = (McpRevocationStatusResult)result.Content!;
        _context.ToolResult = result;
    }

    // ---- Then steps ----

    [Then("the response MUST include a CRL profile name")]
    public void ThenCrlMustHaveProfile()
    {
        Assert.NotNull(_context.CrlResult);
        Assert.NotNull(_context.CrlResult.Profile);
    }

    [Then("the response MUST include a LastUpdate timestamp")]
    public void ThenCrlMustHaveLastUpdate()
    {
        Assert.NotNull(_context.CrlResult);
        Assert.True(_context.CrlResult.LastUpdate != default);
    }

    [Then("the response MUST include a NextUpdate timestamp that is after LastUpdate")]
    public void ThenCrlMustHaveNextUpdateAfterLast()
    {
        Assert.NotNull(_context.CrlResult);
        Assert.True(_context.CrlResult.NextUpdate > _context.CrlResult.LastUpdate);
    }

    [Then("the CRL bytes in the response MUST be base64-encoded")]
    public void ThenCrlBytesMustBeBase64()
    {
        Assert.NotNull(_context.CrlResult);
        Assert.NotNull(_context.CrlResult.CrlBytesBase64);
        Assert.NotEmpty(_context.CrlResult.CrlBytesBase64);
        var crlBytes = Convert.FromBase64String(_context.CrlResult.CrlBytesBase64);
        Assert.NotEmpty(crlBytes);
    }

    [Then("the response profile name MUST be \"(.+)\"")]
    public void ThenCrlProfileMustMatch(string expected)
    {
        Assert.NotNull(_context.CrlResult);
        Assert.Equal(expected, _context.CrlResult.Profile);
    }

    [Then("the status MUST be McpCertificateStatus.Good (.+)")]
    public void ThenOcspStatusMustBeGood(string expectedValueStr)
    {
        int expectedValue = int.Parse(expectedValueStr.Trim('(', ')'));
        Assert.NotNull(_context.OcspResult);
        Assert.True(_context.OcspResult.Status == McpCertificateStatus.Good);
        Assert.Equal(expectedValue, (int)_context.OcspResult.Status);
    }

    [Then("the response MUST include a ThisUpdate and NextUpdate timestamp")]
    public void ThenOcspMustHaveFreshness()
    {
        Assert.NotNull(_context.OcspResult);
        Assert.True(_context.OcspResult.ThisUpdate != default);
        Assert.True(_context.OcspResult.NextUpdate != default);
    }

    [Then("the NextUpdate MUST be after ThisUpdate")]
    public void ThenNextUpdateAfterThis()
    {
        Assert.NotNull(_context.OcspResult);
        Assert.True(_context.OcspResult.NextUpdate > _context.OcspResult.ThisUpdate);
    }

    [Then("the status MUST be McpCertificateStatus.Unknown (.+)")]
    public void ThenOcspStatusMustBeUnknown(string expectedValueStr)
    {
        int expectedValue = int.Parse(expectedValueStr.Trim('(', ')'));
        if (_context.OcspResult != null)
        {
            Assert.True(_context.OcspResult.Status == McpCertificateStatus.Unknown);
            Assert.Equal(expectedValue, (int)_context.OcspResult.Status);
        }
        else if (_context.RevocationStatusResult?.Checks.Count > 0)
        {
            Assert.True(_context.RevocationStatusResult.Checks[0].Status == McpCertificateStatus.Unknown);
            Assert.Equal(expectedValue, (int)_context.RevocationStatusResult.Checks[0].Status);
        }
        else
        {
            throw new Exception("No OcspResult or RevocationStatusResult to check for Unknown status");
        }
    }

    [Then("the Checks array MUST contain one entry")]
    public void ThenChecksMustContainOne()
    {
        Assert.NotNull(_context.RevocationStatusResult);
        Assert.Single(_context.RevocationStatusResult.Checks);
    }

    [Then("the first check result MUST have serial number matching the requested one")]
    public void ThenFirstCheckMustMatchSerial()
    {
        Assert.NotNull(_context.RevocationStatusResult);
        Assert.NotNull(_context.RequestedSerialNumber);
        Assert.Single(_context.RevocationStatusResult.Checks);
        Assert.Equal(_context.RequestedSerialNumber, _context.RevocationStatusResult.Checks[0].SerialNumber);
    }

    [Then("the first check result MUST have status Good")]
    public void ThenFirstCheckMustBeGood()
    {
        Assert.NotNull(_context.RevocationStatusResult);
        Assert.Single(_context.RevocationStatusResult.Checks);
        Assert.Equal(McpCertificateStatus.Good, _context.RevocationStatusResult.Checks[0].Status);
        Assert.True(_context.RevocationStatusResult.Checks[0].FoundInStore);
    }

    [Then("the first check result MUST have FoundInStore equal to true")]
    public void ThenFirstCheckFoundInStoreTrue()
    {
        Assert.NotNull(_context.RevocationStatusResult);
        Assert.NotEmpty(_context.RevocationStatusResult.Checks);
        Assert.True(_context.RevocationStatusResult.Checks[0].FoundInStore);
    }

    [Then("the response MUST have a TotalChecks equal to {int}")]
    public void ThenResponseHasTotalChecks(int expected)
    {
        Assert.NotNull(_context.RevocationStatusResult);
        Assert.Equal(expected, _context.RevocationStatusResult.TotalChecks);
    }

    [Then("FoundInStore MUST be false")]
    public void ThenFoundInStoreMustBeFalse()
    {
        Assert.NotNull(_context.RevocationStatusResult);
        Assert.Single(_context.RevocationStatusResult.Checks);
        Assert.False(_context.RevocationStatusResult.Checks[0].FoundInStore);
    }

    [Then("the Checks array MUST contain at least (.+) entries")]
    public void ThenChecksMustContainAtLeast(int count)
    {
        var result = RequireRevocationStatusResult();
        Assert.True(result.Checks.Count >= count);
    }

    [Then("at least one result MUST have status Good")]
    public void ThenAtLeastOneGood()
    {
        var result = RequireRevocationStatusResult();
        Assert.Contains(result.Checks,
                c => c.Status == McpCertificateStatus.Good);
    }

    [Then("at least one result MUST have status Revoked (.+)")]
    public void ThenAtLeastOneRevoked(string expectedValueStr)
    {
        int expectedValue = int.Parse(expectedValueStr.Trim('(', ')'));
        var result = RequireRevocationStatusResult();
        Assert.Contains(result.Checks,
                c => c.Status == McpCertificateStatus.Revoked);
        Assert.Equal((int)McpCertificateStatus.Revoked, expectedValue);
    }

    [Then("the response profile MUST be \"(.+)\"")]
    public void ThenRevocationProfileMustMatch(string expected)
    {
        if (_context.CrlResult != null)
        {
            Assert.Equal(expected, _context.CrlResult.Profile);
        }
        else
        {
            Assert.NotNull(_context.RevocationStatusResult);
            Assert.Equal(expected, _context.RevocationStatusResult.Profile);
        }
    }

    [Then("the TotalChecks MUST be (.+)")]
    public void ThenTotalChecksMustBe(int expected)
    {
        Assert.NotNull(_context.RevocationStatusResult);
        Assert.Equal(expected, _context.RevocationStatusResult.TotalChecks);
    }
}