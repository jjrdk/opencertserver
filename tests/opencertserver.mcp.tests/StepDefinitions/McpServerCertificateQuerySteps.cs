using System.Security.Cryptography;
using OpenCertServer.Mcp.Tests.Support;
using OpenCertServer.Mcp.Tools;
using Reqnroll;
using Xunit;

namespace OpenCertServer.Mcp.Tests.StepDefinitions;

[Binding]
public sealed class McpServerCertificateQuerySteps
{
    private readonly McpServerFixture _fixture;

    public McpServerCertificateQuerySteps(McpServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Given("a certificate is issued with CN (.+)")]
    public async Task GivenACertificateIsIssuedWithCn(string cn)
    {
        using var rsa = RSA.Create(3072);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            new System.Security.Cryptography.X509Certificates.X500DistinguishedName($"CN={cn}"),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        var csr = Convert.ToBase64String(request.CreateSigningRequest());
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr });
        Assert.True(result.IsSuccess, $"sign_certificate failed: {result.ErrorMessage}");
        TestSharedState.SignedCert = (McpCertificateItem)result.Content!;
    }

    [When("the MCP server invokes \"list_certificates\" with page (.+) and pageSize (.+)")]
    public async Task WhenListWithPageAndPageSize(int page, int pageSize)
    {
        var result = await _fixture.InvokeMcpToolAsync("list_certificates", new { page, pageSize });
        TestSharedState.ToolResult = result;

        if (result.IsSuccess)
        {
            TestSharedState.SearchResult = (McpCertificateSearchResult)result.Content!;
        }
    }

    [When("the MCP server invokes \"search_certificates\" with no filter parameters")]
    public async Task WhenSearchWithNoFilters()
    {
        var result = await _fixture.InvokeMcpToolAsync("search_certificates", new { });
        TestSharedState.ToolResult = result;
        if (result.IsSuccess)
        {
            TestSharedState.SearchResult = (McpCertificateSearchResult)result.Content!;
        }
    }

    [When("the MCP server invokes {string} with serialNumber matching the issued cert")]
    public async Task WhenSearchWithSerialNumber(string toolName)
    {
        if (TestSharedState.SignedCert == null)
        {
            throw new Exception("No cert in shared state — run the Background step first");
        }

        var result = await _fixture.InvokeMcpToolAsync(toolName, new { serialNumber = TestSharedState.SignedCert.SerialNumber });
        TestSharedState.ToolResult = result;
        if (result.IsSuccess)
        {
            TestSharedState.SearchResult = (McpCertificateSearchResult)result.Content!;
        }
    }

    [When("the MCP server invokes \"get_certificate\" with the issued certificate's serial number")]
    public async Task WhenGetBySerial()
    {
        // The serial is in shared state
        if (TestSharedState.SignedCert == null)
        {
            throw new Exception("No signed cert available — run 'Given a certificate is issued' first");
        }

        var serial = TestSharedState.SignedCert.SerialNumber;
        var result = await _fixture.InvokeMcpToolAsync("get_certificate", new { serialNumber = serial });
        TestSharedState.ToolResult = result;
        if (result.IsSuccess)
        {
            TestSharedState.SignedCert = (McpCertificateItem)result.Content!;
        }
    }

    [When("the MCP server invokes \"get_certificate\" with serial number \"(.+)\"")]
    public async Task WhenGetBySpecificSerial(string serial)
    {
        var result = await _fixture.InvokeMcpToolAsync("get_certificate", new { serialNumber = serial });
        TestSharedState.ToolResult = result;
        if (result.IsSuccess)
        {
            TestSharedState.SignedCert = (McpCertificateItem)result.Content!;
        }
    }

    [When("the MCP server invokes \"get_certificate\" without providing a serial number")]
    public async Task WhenGetWithoutSerial()
    {
        var result = await _fixture.InvokeMcpToolAsync("get_certificate", new { });
        TestSharedState.ToolResult = result;
        TestSharedState.SignedCert = result.IsSuccess
            ? (McpCertificateItem)result.Content!
            : null;
    }

    [When("the MCP server invokes \"get_ca_certificates\" with includeFullChain false")]
    public async Task WhenGetCaCertsNoChain()
    {
        var result = await _fixture.InvokeMcpToolAsync("get_ca_certificates", new { includeFullChain = false });
        TestSharedState.ToolResult = result;
        TestSharedState.CaCertsResult = (McpCaCertificatesResult)result.Content!;
    }

    [When("the MCP server invokes \"get_ca_certificates\" with includeFullChain true")]
    public async Task WhenGetCaCertsWithChain()
    {
        var result = await _fixture.InvokeMcpToolAsync("get_ca_certificates", new { includeFullChain = true });
        TestSharedState.ToolResult = result;
        TestSharedState.CaCertsResult = (McpCaCertificatesResult)result.Content!;
    }

    [When("the MCP server invokes \"get_ca_certificates\" with profileName \"(.+)\"")]
    public async Task WhenGetCaCertsWithProfile(string profileName)
    {
        var result =
            await _fixture.InvokeMcpToolAsync("get_ca_certificates", new { profileName, includeFullChain = false });
        TestSharedState.ToolResult = result;
        TestSharedState.CaCertsResult = (McpCaCertificatesResult)result.Content!;
    }

    // ---- Then steps (none overlap with CommonToolsSteps) ----

    [Then("the items list MUST be empty")]
    public void ThenItemsListMustBeEmpty()
    {
        Assert.NotNull(TestSharedState.SearchResult);
        Assert.Empty(TestSharedState.SearchResult.Items);
    }

    [Then("the items list MUST contain exactly (.+) certificate")]
    public void ThenItemsMustContainExactly(int count)
    {
        Assert.NotNull(TestSharedState.SearchResult);
        Assert.Equal(count, TestSharedState.SearchResult.Items.Count);
    }

    [Then("the items list MUST contain at most (.+) certificate")]
    public void ThenItemsMustContainAtMost(int count)
    {
        Assert.NotNull(TestSharedState.SearchResult);
        Assert.True(TestSharedState.SearchResult.Items.Count <= count);
    }

    [Then("the items list MUST contain at least (.+) certificate")]
    public void ThenItemsMustContainAtLeast(int count)
    {
        Assert.NotNull(TestSharedState.SearchResult);
        Assert.True(TestSharedState.SearchResult.Items.Count >= count);
    }

    [Then("each returned certificate MUST have a non-empty serial number")]
    public void ThenEachItemMustHaveSerial()
    {
        Assert.NotNull(TestSharedState.SearchResult);
        foreach (var item in TestSharedState.SearchResult.Items)
        {
            Assert.NotNull(item.SerialNumber);
            Assert.NotEmpty(item.SerialNumber);
        }
    }

    [Then("each returned certificate MUST have a non-empty subject")]
    public void ThenEachItemMustHaveSubject()
    {
        Assert.NotNull(TestSharedState.SearchResult);
        foreach (var item in TestSharedState.SearchResult.Items)
        {
            Assert.NotNull(item.Subject);
            Assert.NotEmpty(item.Subject);
        }
    }

    [Then("each returned certificate MUST have a non-empty issuer")]
    public void ThenEachItemMustHaveIssuer()
    {
        Assert.NotNull(TestSharedState.SearchResult);
        foreach (var item in TestSharedState.SearchResult.Items)
        {
            Assert.NotNull(item.Issuer);
            Assert.NotEmpty(item.Issuer);
        }
    }

    [Then("each returned certificate MUST have a non-empty thumbprint")]
    public void ThenEachItemMustHaveThumbprint()
    {
        Assert.NotNull(TestSharedState.SearchResult);
        foreach (var item in TestSharedState.SearchResult.Items)
        {
            Assert.NotNull(item.Thumbprint);
            Assert.NotEmpty(item.Thumbprint);
        }
    }

    [Then("each returned certificate must have serial number, subject, issuer, and thumbprint")]
    public void ThenEachItemMustHaveMetadata()
    {
        ThenEachItemMustHaveSerial();
        ThenEachItemMustHaveSubject();
        ThenEachItemMustHaveIssuer();
        ThenEachItemMustHaveThumbprint();
    }

    [Then("each returned certificate MUST have a valid NotBefore timestamp")]
    public void ThenMustHaveValidNotBefore()
    {
        Assert.NotNull(TestSharedState.SearchResult);
        foreach (var item in TestSharedState.SearchResult.Items)
        {
            Assert.True(item.NotBefore != default, "NotBefore is default zero");
        }
    }

    [Then("each returned certificate MUST have a valid NotAfter timestamp")]
    public void ThenMustHaveValidNotAfter()
    {
        Assert.NotNull(TestSharedState.SearchResult);
        foreach (var item in TestSharedState.SearchResult.Items)
        {
            Assert.True(item.NotAfter != default, "NotAfter is default zero");
        }
    }

    [Then("NotBefore must be before NotAfter")]
    public void ThenNotBeforeBeforeNotAfter()
    {
        Assert.NotNull(TestSharedState.SearchResult);
        foreach (var item in TestSharedState.SearchResult.Items)
        {
            Assert.True(item.NotBefore < item.NotAfter);
        }
    }

    [Then("hasNextPage indicates whether there are more pages")]
    public void ThenHasNextPageValid()
    {
        Assert.NotNull(TestSharedState.SearchResult);
        _ = TestSharedState.SearchResult.HasNextPage;
    }

    [Then("the returned certificate MUST have a non-empty serial number")]
    public void ThenReturnedCertMustHaveSerial()
    {
        Assert.NotNull(TestSharedState.SignedCert);
        Assert.NotEmpty(TestSharedState.SignedCert.SerialNumber);
    }

    [Then("the returned certificate subject MUST be present")]
    public void ThenSubjectMustBePresent()
    {
        Assert.NotNull(TestSharedState.SignedCert);
        Assert.NotEmpty(TestSharedState.SignedCert.Subject);
    }

    [Then("the returned certificate thumbprint MUST be present")]
    public void ThenThumbprintMustBePresent()
    {
        Assert.NotNull(TestSharedState.SignedCert);
        Assert.NotEmpty(TestSharedState.SignedCert.Thumbprint);
    }

    [Then("the result MUST contain at least (.+) certificate")]
    public void ThenCaCertsMustContainAtLeast(int count)
    {
        Assert.NotNull(TestSharedState.CaCertsResult);
        Assert.True(TestSharedState.CaCertsResult.Certificates.Count >= count);
    }

    [Then("each CA certificate MUST have a subject, issuer, serial number, and thumbprint")]
    public void ThenEachCaCertMustHaveMetadata()
    {
        if (TestSharedState.CaCertsResult == null)
        {
            return;
        }

        foreach (var cert in TestSharedState.CaCertsResult.Certificates)
        {
            Assert.NotNull(cert.Subject);
            Assert.NotEmpty(cert.Subject);
            Assert.NotNull(cert.Issuer);
            Assert.NotEmpty(cert.Issuer);
            Assert.NotNull(cert.SerialNumber);
            Assert.NotEmpty(cert.SerialNumber);
            Assert.NotNull(cert.Thumbprint);
            Assert.NotEmpty(cert.Thumbprint);
        }
    }

    [Then("the certificate count MUST be greater than or equal to 1")]
    public void ThenCertCountMustBeAtLeast1()
    {
        if (TestSharedState.CaCertsResult != null)
        {
            Assert.True(TestSharedState.CaCertsResult.Certificates.Count >= 1);
        }
    }

    [Then("the profiles list MUST include \"(.+)\"")]
    public void ThenProfilesMustIncludeProfile(string name)
    {
        Assert.NotNull(TestSharedState.CaCertsResult);
        Assert.Contains(name, TestSharedState.CaCertsResult.Profiles);
    }
}
