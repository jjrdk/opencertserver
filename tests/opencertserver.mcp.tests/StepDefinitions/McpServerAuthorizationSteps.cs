namespace OpenCertServer.Mcp.Tests.StepDefinitions;

using OpenCertServer.Mcp;
using OpenCertServer.Mcp.Tests;
using OpenCertServer.Mcp.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>
/// BDD coverage for security-review finding the CA-mutating MCP tools
/// (sign_certificate, revoke_certificate) must require an authenticated, authorized
/// caller and the CA surface must fail closed by default.
/// </summary>
[Binding]
public sealed class McpServerAuthorizationSteps
{
    private readonly McpServerFixture _fixture;
    private readonly McpScenarioContext _context;

    public McpServerAuthorizationSteps(McpServerFixture fixture, McpScenarioContext context)
    {
        _fixture = fixture;
        _context = context;
    }

    // ------------------------------------------------------------------
    // Given: caller toggles (fail-closed default exercises)
    // ------------------------------------------------------------------

    [Given(@"the MCP server has no authenticated caller")]
    public void GivenNoAuthenticatedCaller()
    {
        _fixture.UseUnauthenticatedCaller();
    }

    [Given(@"the MCP server has an authenticated caller without the CA-admin role")]
    public void GivenAuthenticatedNonAdminCaller()
    {
        _fixture.UseAuthenticatedNonAdminCaller();
    }

    [Given(@"the MCP server has an authenticated CA-admin caller")]
    public void GivenAuthenticatedAdminCaller()
    {
        _fixture.UseAuthenticatedAdminCaller();
    }

    [Given(@"a certificate is issued by an admin caller")]
    public async Task GivenCertificateIssuedByAdmin()
    {
        // Issue as an admin so that the serial exists for later revoke attempts,
        // regardless of which caller is active afterward.
        _fixture.UseAuthenticatedAdminCaller();
        var csr = McpServerFixture.CreateBase64DerCsr();
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr }).ConfigureAwait(false);
        Assert.True(result.IsSuccess, $"sign_certificate failed: {result.ErrorMessage}");
        var cert = (McpCertificateItem)result.Content!;
        _context.IssuedSerialNumber = cert.SerialNumber;
        _context.SignedCert = cert;
    }

    // ------------------------------------------------------------------
    // Given: fail-closed CA-operation configuration
    // ------------------------------------------------------------------

    [Given(@"the MCP server has CA operations enabled")]
    public void GivenCaOperationsEnabled()
    {
        _context.McpConfigurationOptions ??= new McpServerOptions();
        _context.McpConfigurationOptions.EnableCaOperations = true;
    }

    [Given(@"no authentication token is configured")]
    public void GivenNoAuthToken()
    {
        var options = _context.McpConfigurationOptions ??= new McpServerOptions { EnableCaOperations = true };
        options.AuthenticationToken = null;
    }

    [Given(@"an authentication token is configured")]
    public void GivenAuthToken()
    {
        var options = _context.McpConfigurationOptions ??= new McpServerOptions { EnableCaOperations = true };
        options.AuthenticationToken = "configured-shared-secret";
    }

    [Given(@"the self-signed test CA is not allowed")]
    public void GivenSelfSignedNotAllowed()
    {
        var options = _context.McpConfigurationOptions ??= new McpServerOptions { EnableCaOperations = true };
        options.AllowSelfSignedTestCa = false;
    }

    [Given(@"the self-signed test CA is allowed")]
    public void GivenSelfSignedAllowed()
    {
        var options = _context.McpConfigurationOptions ??= new McpServerOptions { EnableCaOperations = true };
        options.AllowSelfSignedTestCa = true;
    }

    // ------------------------------------------------------------------
    // When
    // ------------------------------------------------------------------

    [When(@"the MCP server invokes ""sign_certificate"" with a valid CSR")]
    public async Task WhenSignValidCsr()
    {
        var csr = McpServerFixture.CreateBase64DerCsr();
        var result = await _fixture.InvokeMcpToolAsync("sign_certificate", new { csr }).ConfigureAwait(false);
        _context.ToolResult = result;
        if (result.IsSuccess && result.Content is McpCertificateItem cert)
        {
            _context.IssuedSerialNumber = cert.SerialNumber;
            _context.SignedCert = cert;
        }
    }

    [When(@"the MCP server invokes ""revoke_certificate"" with an issued certificate's serial number")]
    public async Task WhenRevokeIssuedSerial()
    {
        var serial = _context.IssuedSerialNumber
            ?? throw new InvalidOperationException("An issued serial number is required; run a 'Given a certificate is issued' step first.");
        var result = await _fixture.InvokeMcpToolAsync(
            "revoke_certificate",
            new { serialNumber = serial, reason = "KeyCompromise" }).ConfigureAwait(false);
        _context.ToolResult = result;
    }

    [When(@"the MCP server configuration is validated")]
    public void WhenConfigurationValidated()
    {
        var options = _context.McpConfigurationOptions ?? new McpServerOptions();
        try
        {
            var result = McpServerConfiguration.EnsureConfigured(options);
            _context.McpConfigurationStartupAllowed = result == McpServerConfigurationResult.Enabled;
        }
        catch (Exception ex)
        {
            _context.McpConfigurationError = ex;
            _context.McpConfigurationStartupAllowed = false;
        }
    }

    // ------------------------------------------------------------------
    // Then: caller-rejection assertions
    // ------------------------------------------------------------------

    [Then(@"the error message MUST indicate the caller is not authorized")]
    public void ThenErrorIndicatesNotAuthorized()
    {
        var r = _context.ToolResult;
        Assert.NotNull(r);
        Assert.False(r.IsSuccess, $"Expected rejection but the tool succeeded: {r.Content}");
        var msg = r.ErrorMessage ?? "";
        Assert.True(
            msg.Contains("authorized", StringComparison.OrdinalIgnoreCase),
            $"'{msg}' does not indicate that the caller is not authorized");
    }

    [Then(@"the error message MUST mention the CA-admin role")]
    public void ThenErrorMentionsCaAdminRole()
    {
        var r = _context.ToolResult;
        Assert.NotNull(r);
        Assert.False(r.IsSuccess, $"Expected rejection but the tool succeeded: {r.Content}");
        var msg = r.ErrorMessage ?? "";
        Assert.True(
            msg.Contains("ca-admin", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("ca_admin", StringComparison.OrdinalIgnoreCase),
            $"'{msg}' does not mention the CA-admin role");
    }

    // ------------------------------------------------------------------
    // Then: fail-closed configuration assertions
    // ------------------------------------------------------------------

    [Then(@"startup MUST be refused")]
    public void ThenStartupRefused()
    {
        Assert.False(_context.McpConfigurationStartupAllowed);
        Assert.NotNull(_context.McpConfigurationError);
    }

    [Then(@"startup MUST be allowed")]
    public void ThenStartupAllowed()
    {
        Assert.True(_context.McpConfigurationStartupAllowed);
        Assert.Null(_context.McpConfigurationError);
    }

    [Then(@"the refusal reason MUST mention the authentication token")]
    public void ThenRefusalMentionsAuthToken()
    {
        var ex = _context.McpConfigurationError
            ?? throw new Exception("Expected a configuration validation error but none was recorded.");
        Assert.True(
            ex.Message.Contains("AuthenticationToken", StringComparison.OrdinalIgnoreCase),
            $"'{ex.Message}' does not mention the missing authentication token");
    }

    [Then(@"the refusal reason MUST mention an access-controlled CA")]
    public void ThenRefusalMentionsAccessControlledCa()
    {
        var ex = _context.McpConfigurationError
            ?? throw new Exception("Expected a configuration validation error but none was recorded.");
        Assert.True(
            ex.Message.Contains("access-controlled", StringComparison.OrdinalIgnoreCase),
            $"'{ex.Message}' does not mention that a real, access-controlled CA is required");
    }
}
