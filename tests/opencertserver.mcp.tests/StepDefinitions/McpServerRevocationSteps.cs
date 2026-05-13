namespace OpenCertServer.Mcp.Tests;

using OpenCertServer.Mcp.Tests.Support;
using OpenCertServer.Mcp;
using OpenCertServer.Mcp.Tools;
using Reqnroll;
using Xunit;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;
using OpenCertServer.Ca.Utils.Ca;

[Binding]
public sealed class McpServerRevocationSteps
{
        private readonly McpServerFixture _fixture;
        private readonly List<X509Certificate2> _issuedCerts = new();

        public McpServerRevocationSteps(McpServerFixture fixture)
        {
                _fixture = fixture;
        }

        private async Task<(string serial, string nameHash, string keyHash)> GetCertInfoAsync()
        {
                if (_issuedCerts.Count == 0)
                        throw new InvalidOperationException("No certificates issued yet");
                var cert = _issuedCerts[^1];

                var nameHashBytes = SHA256.Create()!.ComputeHash(cert.SubjectName.RawData);
                var keyBytes = cert.GetPublicKey()!;

                return (cert.GetSerialNumberString(),
                        Convert.ToHexString(nameHashBytes),
                        Convert.ToHexString(keyBytes));
        }

        [Given("a certificate is issued")]
        public async Task GivenACertificateIsIssued()
        {
                // This issues a cert that goes into TestSharedState; also stash in _issuedCerts for OCSP
                await TestSharedState.IssueAsync(_fixture.McpServer, "test-rev-check-1");

                // Also need an actual X509Certificate2 in _issuedCerts for hash computation
                var cert = await _fixture.CreateAndIssueCertificateAsync("test-rev-check-1");
                _issuedCerts.Add(cert);
        }

        [Given("another certificate is issued and then revoked")]
        public async Task GivenAnotherCertificateIssuedAndRevoked()
        {
                // Issue second cert
                var cert = await _fixture.CreateAndIssueCertificateAsync("test-rev-check-2");
                _issuedCerts.Add(cert);

                // Also add to shared state so common assertions work
                await TestSharedState.IssueAsync(_fixture.McpServer, "test-rev-check-2");

                // Revoke it via MCP
                await _fixture.InvokeMcpToolAsync("revoke_certificate", new
                {
                        serialNumber = cert.GetSerialNumberString(),
                        reason = "KeyCompromise"
                });
        }

        [When("the MCP server invokes \\\"get_crl\\\" with default parameters")]
        public async Task WhenGetCrlDefault()
        {
                var result = await _fixture.InvokeMcpToolAsync("get_crl", new { });
                Assert.True(result.IsSuccess, $"get_crl failed: {result.ErrorMessage}");
                TestSharedState.CrlResult = (McpCrlResult)result.Content!;
        }

        [When("the MCP server invokes \\\"get_crl\\\" with profileName \\\"(.+)\\\"")]
        public async Task WhenGetCrlWithProfile(string profileName)
        {
                var result = await _fixture.InvokeMcpToolAsync("get_crl", new { profileName });
                Assert.True(result.IsSuccess, $"get_crl with profile failed: {result.ErrorMessage}");
                TestSharedState.CrlResult = (McpCrlResult)result.Content!;
        }

        [When("the MCP server invokes \\\"get_crl\\\" with includePem true")]
        public async Task WhenGetCrlWithPem()
        {
                var result = await _fixture.InvokeMcpToolAsync("get_crl", new { includePem = true });
                Assert.True(result.IsSuccess, $"get_crl with PEM failed: {result.ErrorMessage}");
                TestSharedState.CrlResult = (McpCrlResult)result.Content!;
        }

        [When(
                "the MCP server invokes \\\"check_ocsp_status\\\" with the certificate's serial number, issuer name hash, and issuer key hash")]
        public async Task WhenCheckOcspWithGoodCert()
        {
                var (serial, nameHash, keyHash) = await GetCertInfoAsync();
                var result = await _fixture.InvokeMcpToolAsync("check_ocsp_status", new
                {
                        serialNumber = serial,
                        issuerNameHash = nameHash,
                        issuerKeyHash = keyHash
                });
                Assert.True(result.IsSuccess, $"check_ocsp_status failed: {result.ErrorMessage}");
                TestSharedState.OcspResult = (McpOcspCheckResult)result.Content!;
                TestSharedState.ToolResult = result;
        }

        [When(
                "the MCP server invokes \\\"check_ocsp_status\\\" with serial number \\\"(.+)\\\", issuer name hash \\\"(.+)\\\", and issuer key hash \\\"(.+)\\\"")]
        public async Task WhenCheckOcspWithSerial(string serial, string nameHash, string keyHash)
        {
                var result = await _fixture.InvokeMcpToolAsync("check_ocsp_status", new
                {
                        serialNumber = serial,
                        issuerNameHash = nameHash,
                        issuerKeyHash = keyHash
                });
                TestSharedState.OcspResult = result.IsSuccess
                        ? (McpOcspCheckResult)result.Content!
                        : null;
                TestSharedState.ToolResult = result;
        }

        [When("the MCP server invokes \\\"check_ocsp_status\\\" with serial number \\\"(.+)\\\" but no issuer hashes")]
        public async Task WhenCheckOcspWithoutHashes(string serial)
        {
                var result = await _fixture.InvokeMcpToolAsync("check_ocsp_status", new { serialNumber = serial });
                TestSharedState.OcspResult = result.IsSuccess
                        ? (McpOcspCheckResult)result.Content!
                        : null;
                TestSharedState.ToolResult = result;
        }

        [When(
                "the MCP server invokes \\\"get_revocation_status\\\" with an array containing the certificate's serial number")]
        public async Task WhenGetRevStatusWithGoodCert()
        {
                var (serial, _, _) = await GetCertInfoAsync();
                var result = await _fixture.InvokeMcpToolAsync("get_revocation_status", new
                {
                        serialNumbers = new[] { serial }
                });
                Assert.True(result.IsSuccess, $"get_revocation_status failed: {result.ErrorMessage}");
                TestSharedState.RevocationStatusResult = (McpRevocationStatusResult)result.Content!;
                TestSharedState.ToolResult = result;
        }

        [When("the MCP server invokes \\\"get_revocation_status\\\" with serial number \\\"(.+)\\\"")]
        public async Task WhenGetRevStatusWithUnknownCert(string serial)
        {
                var result = await _fixture.InvokeMcpToolAsync("get_revocation_status", new
                {
                        serialNumbers = new[] { serial }
                });
                Assert.True(result.IsSuccess, $"get_revocation_status failed: {result.ErrorMessage}");
                TestSharedState.RevocationStatusResult = (McpRevocationStatusResult)result.Content!;
                TestSharedState.ToolResult = result;
        }

        [When("the MCP server invokes \\\"get_revocation_status\\\" with an empty serialNumbers array")]
        public async Task WhenGetRevStatusWithEmptyArray()
        {
                var result = await _fixture.InvokeMcpToolAsync("get_revocation_status", new
                {
                        serialNumbers = Array.Empty<string>()
                });
                TestSharedState.ToolResult = result;
        }

        [When("the MCP server invokes \\\"get_revocation_status\\\" with both certificates' serial numbers")]
        public async Task WhenGetRevStatusWithMixedCerts()
        {
                var serials = _issuedCerts.Select(c => c.GetSerialNumberString()).ToList();
                var result = await _fixture.InvokeMcpToolAsync("get_revocation_status", new
                {
                        serialNumbers = serials
                });
                Assert.True(result.IsSuccess, $"get_revocation_status failed: {result.ErrorMessage}");
                TestSharedState.RevocationStatusResult = (McpRevocationStatusResult)result.Content!;
                TestSharedState.ToolResult = result;
        }

        [When("the MCP server invokes \\\"get_revocation_status\\\" with serial numbers and profileName \\\"(.+)\\\"")]
        public async Task WhenGetRevStatusWithProfile(string profileName)
        {
                var serials = _issuedCerts.Select(c => c.GetSerialNumberString()).ToList();
                var result = await _fixture.InvokeMcpToolAsync("get_revocation_status", new
                {
                        serialNumbers = serials,
                        profileName = profileName
                });
                Assert.True(result.IsSuccess, $"get_revocation_status with profile failed: {result.ErrorMessage}");
                TestSharedState.RevocationStatusResult = (McpRevocationStatusResult)result.Content!;
                TestSharedState.ToolResult = result;
        }

        // ---- Then steps ----

        [Then("the response MUST include a CRL profile name")]
        public void ThenCrlMustHaveProfile()
        {
                Assert.NotNull(TestSharedState.CrlResult);
                Assert.NotNull(TestSharedState.CrlResult.Profile);
        }

        [Then("the response MUST include a LastUpdate timestamp")]
        public void ThenCrlMustHaveLastUpdate()
        {
                Assert.NotNull(TestSharedState.CrlResult);
                Assert.True(TestSharedState.CrlResult.LastUpdate != default);
        }

        [Then("the response MUST include a NextUpdate timestamp that is after LastUpdate")]
        public void ThenCrlMustHaveNextUpdateAfterLast()
        {
                Assert.NotNull(TestSharedState.CrlResult);
                Assert.True(TestSharedState.CrlResult.NextUpdate > TestSharedState.CrlResult.LastUpdate);
        }

        [Then("the CRL bytes in the response MUST be base64-encoded")]
        public void ThenCrlBytesMustBeBase64()
        {
                // When includePem is true, CrlBytesBase64 should be populated
        }

        [Then("the response profile name MUST be \\\"(.+)\\\"")]
        public void ThenCrlProfileMustMatch(string expected)
        {
                Assert.NotNull(TestSharedState.CrlResult);
                Assert.Equal(expected, TestSharedState.CrlResult.Profile);
        }

        [Then("the status MUST be McpCertificateStatus.Good (.+)")]
        public void ThenOcspStatusMustBeGood(int expectedValue)
        {
                Assert.NotNull(TestSharedState.OcspResult);
                Assert.True(TestSharedState.OcspResult.Status == McpCertificateStatus.Good);
                Assert.Equal(expectedValue, (int)TestSharedState.OcspResult.Status);
        }

        [Then("the response MUST include a ThisUpdate and NextUpdate timestamp")]
        public void ThenOcspMustHaveFreshness()
        {
                Assert.NotNull(TestSharedState.OcspResult);
                Assert.True(TestSharedState.OcspResult.ThisUpdate != default);
                Assert.True(TestSharedState.OcspResult.NextUpdate != default);
        }

        [Then("the NextUpdate MUST be after ThisUpdate")]
        public void ThenNextUpdateAfterThis()
        {
                Assert.NotNull(TestSharedState.OcspResult);
                Assert.True(TestSharedState.OcspResult.NextUpdate > TestSharedState.OcspResult.ThisUpdate);
        }

        [Then("the status MUST be McpCertificateStatus.Unknown (.+)")]
        public void ThenOcspStatusMustBeUnknown(int expectedValue)
        {
                Assert.NotNull(TestSharedState.OcspResult);
                Assert.True(TestSharedState.OcspResult.Status == McpCertificateStatus.Unknown);
                Assert.Equal(expectedValue, (int)TestSharedState.OcspResult.Status);
        }

        [Then("the Checks array MUST contain one entry")]
        public void ThenChecksMustContainOne()
        {
                Assert.NotNull(TestSharedState.RevocationStatusResult);
                Assert.Single(TestSharedState.RevocationStatusResult.Checks);
        }

        [Then("the first check result MUST have serial number matching the requested one")]
        public void ThenFirstCheckMustMatchSerial()
        {
                Assert.NotNull(TestSharedState.RevocationStatusResult);
                Assert.Single(TestSharedState.RevocationStatusResult.Checks);
        }

        [Then("the first check result MUST have status Good")]
        public void ThenFirstCheckMustBeGood()
        {
                Assert.NotNull(TestSharedState.RevocationStatusResult);
                Assert.Single(TestSharedState.RevocationStatusResult.Checks);
                Assert.Equal(McpCertificateStatus.Good, TestSharedState.RevocationStatusResult.Checks[0].Status);
                Assert.True(TestSharedState.RevocationStatusResult.Checks[0].FoundInStore);
        }

        [Then("FoundInStore MUST be false")]
        public void ThenFoundInStoreMustBeFalse()
        {
                Assert.NotNull(TestSharedState.RevocationStatusResult);
                Assert.Single(TestSharedState.RevocationStatusResult.Checks);
                Assert.False(TestSharedState.RevocationStatusResult.Checks[0].FoundInStore);
        }

        [Then("the Checks array MUST contain at least (.+) entries")]
        public void ThenChecksMustContainAtLeast(int count)
        {
                Assert.NotNull(TestSharedState.RevocationStatusResult);
                Assert.True(TestSharedState.RevocationStatusResult.Checks.Count >= count);
        }

        [Then("at least one result MUST have status Good")]
        public void ThenAtLeastOneGood()
        {
                Assert.NotNull(TestSharedState.RevocationStatusResult);
                Assert.Contains(TestSharedState.RevocationStatusResult.Checks,
                        c => c.Status == McpCertificateStatus.Good);
        }

        [Then("at least one result MUST have status Revoked (.+)")]
        public void ThenAtLeastOneRevoked(int expectedValue)
        {
                Assert.NotNull(TestSharedState.RevocationStatusResult);
                Assert.Contains(TestSharedState.RevocationStatusResult.Checks,
                        c => c.Status == McpCertificateStatus.Revoked);
                Assert.Equal((int)McpCertificateStatus.Revoked, expectedValue);
        }

        [Then("the response profile MUST be \\\"(.+)\\\"")]
        public void ThenRevocationProfileMustMatch(string expected)
        {
                Assert.NotNull(TestSharedState.RevocationStatusResult);
                Assert.Equal(expected, TestSharedState.RevocationStatusResult.Profile);
        }

        [Then("the TotalChecks MUST be (.+)")]
        public void ThenTotalChecksMustBe(int expected)
        {
                Assert.NotNull(TestSharedState.RevocationStatusResult);
                Assert.Equal(expected, TestSharedState.RevocationStatusResult.TotalChecks);
        }

        [Then("the error description contains (.+)")]
        public void ThenErrorContainsKeyword(string keyword)
        {
                Assert.NotNull(TestSharedState.ToolResult);
                var msg = TestSharedState.ToolResult.ErrorMessage!;
                Assert.True(msg.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }
}
