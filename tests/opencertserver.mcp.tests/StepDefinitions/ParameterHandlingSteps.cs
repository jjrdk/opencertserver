using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Mcp.Tests.StepDefinitions;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using OpenCertServer.Ca;
using OpenCertServer.Mcp.Tests.Support;
using Reqnroll;
using Xunit;

[Binding]
public class ParameterHandlingSteps
{
    private readonly McpServerFixture _fixture;

    public ParameterHandlingSteps(McpServerFixture fixture)
    {
        _fixture = fixture;
    }

    [When(@"the MCP server invokes ""([^""]*)"" with parameters:")]
    public async Task WhenInvokeWithParameters(string toolName, Table table)
    {
        var parameters = new Dictionary<string, object>();
        foreach (var row in table.Rows)
        {
            var key = row[0];
            var value = row[1];

            // Handle special placeholders
            if (value == "{issued_serial}")
            {
                value = TestSharedState.IssuedSerialNumber ?? "0000";
            }
            else if (value.StartsWith("[") && value.EndsWith("]"))
            {
                // Parse as JSON array — serial numbers are strings, so quote them
                var arrayValue = value.Replace("{issued_serial}",
                    $@"""{TestSharedState.IssuedSerialNumber ?? "0000"}""");
                var jsonArray = JsonSerializer.Deserialize<JsonElement>(arrayValue);
                parameters[key] = jsonArray;
                continue;
            }
            else if (value.Equals("true", StringComparison.OrdinalIgnoreCase))
            {
                parameters[key] = true;
                continue;
            }
            else if (value.Equals("false", StringComparison.OrdinalIgnoreCase))
            {
                parameters[key] = false;
                continue;
            }
            else if (int.TryParse(value, out var intValue))
            {
                parameters[key] = intValue;
                continue;
            }

            parameters[key] = value;
        }

        var result = await _fixture.InvokeMcpToolAsync(toolName, parameters);
        TestSharedState.ToolResult = result;
    }

    [Given("the MCP server is initialized with a test CA")]
    public void GivenTheMCPServerIsInitializedWithATestCA()
    {
        // Fixture is auto-initialized by Reqnroll via dependency injection.
        // This step is a no-op placeholder to satisfy the Background requirement.
        // Clears any leftover state from previous scenarios.
        TestSharedState.Clear();
    }

    [When(@"the MCP server invokes ""([^""]*)"" with a PEM CSR")]
    public async Task WhenInvokeWithPemCsr(string toolName)
    {
        // Generate a test CSR in PEM format
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Test PEM CSR",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var csrBytes = request.CreateSigningRequest();
        var pemCsr = $"-----BEGIN CERTIFICATE REQUEST-----\n{Convert.ToBase64String(csrBytes)}\n-----END CERTIFICATE REQUEST-----";

        var parameters = new Dictionary<string, object>
        {
            ["csr"] = pemCsr
        };

        var result = await _fixture.InvokeMcpToolAsync(toolName, parameters);
        TestSharedState.ToolResult = result;
        if (result.IsSuccess && result.Content is McpCertificateItem cert)
        {
            TestSharedState.SignedCert = cert;
        }
    }

    [When(@"the MCP server invokes ""([^""]*)"" with ISO 8601 dates")]
    public async Task WhenInvokeWithIso8601Dates(string toolName)
    {
        // Generate a test CSR
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Test ISO Dates",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var csrBytes = request.CreateSigningRequest();
        var csrBase64 = Convert.ToBase64String(csrBytes);

        // Use ISO 8601 dates with timezone
        var notBefore = DateTimeOffset.UtcNow.ToString("o");
        var notAfter = DateTimeOffset.UtcNow.AddDays(30).ToString("o");

        var parameters = new Dictionary<string, object>
        {
            ["csr"] = csrBase64,
            ["notBefore"] = notBefore,
            ["notAfter"] = notAfter
        };

        var result = await _fixture.InvokeMcpToolAsync(toolName, parameters);
        TestSharedState.ToolResult = result;
        if (result.IsSuccess && result.Content is McpCertificateItem cert)
        {
            TestSharedState.SignedCert = cert;
        }
    }

    [Given(@"a certificate has been issued")]
    public async Task GivenCertificateIssued()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Test Certificate",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var result = await _fixture.CertificateAuthority.SignCertificateRequest(
            request,
            profileName: null,
            requestor: null,
            reenrollingFrom: null,
            notBefore: null,
            notAfter: null,
            CancellationToken.None);

        if (result is SignCertificateResponse.Success success)
        {
            TestSharedState.IssuedSerialNumber = success.Certificate.GetSerialNumberString();
        }
        else
        {
            throw new Exception("Failed to issue test certificate");
        }
    }

    [Then("the error message MUST mention {string}")]
    public void ThenTheErrorMessageMUSTMention(string keyword)
    {
        var r = TestSharedState.ToolResult;
        Assert.NotNull(r);
        Assert.False(r.IsSuccess);
        var msg = r.ErrorMessage ?? "";
        Assert.True(msg.Contains(keyword, StringComparison.OrdinalIgnoreCase),
            $"Error '{msg}' does not mention '{keyword}'");
    }
}
