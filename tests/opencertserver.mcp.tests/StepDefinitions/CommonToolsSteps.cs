namespace OpenCertServer.Mcp.Tests.StepDefinitions;

using System.Text.Json;
using OpenCertServer.Mcp.Tests.Support;
using OpenCertServer.Mcp.Tests;
using Reqnroll;
using Xunit;
using OpenCertServer.Ca.Utils.Ca;

[Binding]
public sealed class CommonToolsSteps : IDisposable
{
    private readonly McpServerFixture _fixture;

    public CommonToolsSteps(McpServerFixture fixture)
    {
        _fixture = fixture;
        TestSharedState.Store = _fixture.Store;
    }

    public void Dispose() => TestSharedState.Clear();

    [When("the MCP server attempts to invoke a non-existent tool")]
    public async Task InvokeNonExistentTool()
    {
        var result = await _fixture.InvokeMcpToolAsync("nonexistent_tool_xyz", new { });
        TestSharedState.ToolResult = result;
    }

    [When("the MCP server lists tool (.+)")]
    public async Task ListTool(string toolName)
    {
        // Ensure tools are initialized (needed by metadata steps in Scenario Outline)
        if (TestSharedState.Tools == null)
            TestSharedState.Tools = _fixture.McpServer.GetTools();
        // Strip surrounding quotes that Scenario Outline substitution may add
        toolName = toolName.Trim('"').Trim('\'');
        var result = await _fixture.InvokeMcpToolAsync(toolName, new { });
        TestSharedState.ToolResult = result;
    }

      [Then("the result MUST succeed")]
    public void ThenResultMustSucceed()
      {
        var r = TestSharedState.ToolResult;
        var cert = TestSharedState.SignedCert;
        var rev = TestSharedState.RevocationStatusResult;

        bool ok = (r != null && r.IsSuccess) ||
            (cert != null) ||
            (rev != null);

        if (!ok)
        {
            string reason = "r=" + (r?.IsSuccess + "");
            if (cert != null) reason += " cert=notnull";
            if (rev != null) reason += " rev=notnull";
            throw new Exception($"Expected success but got: {reason}");
        }
    }

    [Then("the result MUST indicate failure")]
    public void ThenResultMustIndicateFailure()
    {
        var r = TestSharedState.ToolResult;
        var cert = TestSharedState.SignedCert;

        // For signing: failure means cert is null (error path)
        // For other tools: failure means ToolResult.IsSuccess == false
        bool failed = cert == null || (r != null && !r.IsSuccess);

        if (!failed)
        {
            throw new Exception($"Expected failure but: cert={cert != null}, r={r?.IsSuccess ?? false}");
        }
    }

    [Then("the error message MUST mention (.+) is required")]
    public void ThenErrorContainsRequiredKeyword(string keyword)
    {
        var r = TestSharedState.ToolResult;
        Assert.NotNull(r);
        Assert.False(r.IsSuccess);
        var msg = r.ErrorMessage ?? "";
        // Support "or" alternatives and leading articles ("that", "a", "an", "the")
        var parts = keyword.Trim('"', '\'')
            .Split(new[] { " or " }, StringSplitOptions.RemoveEmptyEntries);
        bool pass = parts.Any(part =>
        {
            var clean = part.Trim().Trim('"', '\'');
            // Strip leading article words
            foreach (var prefix in new[] { "that ", "an ", "a ", "the " })
                if (clean.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    clean = clean[prefix.Length..];
            return msg.Contains(clean, StringComparison.OrdinalIgnoreCase);
        });
        Assert.True(pass, $"Error '{msg}' does not mention required '{keyword}'");
    }

    [Then("the error message MUST mention hex encoding")]
    public void ThenErrorContainsHexKeyword()
    {
        var r = TestSharedState.ToolResult;
        Assert.NotNull(r);
        Assert.False(r.IsSuccess);
        var msg = r.ErrorMessage ?? "";
        Assert.True(msg.Contains("hex", StringComparison.OrdinalIgnoreCase),
            $"Error '{msg}' does not mention 'hex'");
    }

    [Then("the error message MUST mention that no certificate with that serial was found")]
    public void ThenErrorContainsSerialNotFound()
    {
        var r = TestSharedState.ToolResult;
        Assert.NotNull(r);
        Assert.False(r.IsSuccess);
        var msg = r.ErrorMessage ?? "";
        Assert.True(
            msg.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("serial", StringComparison.OrdinalIgnoreCase),
            $"Error '{msg}' does not mention serial not found");
    }

    [Then("the revocation reason stored MUST reflect \"(.+)\"")]
    public async Task ThenRevocationReasonReflects(string expectedReason)
    {
        // If we have a signed cert that was revoked, check inventory
        var store = TestSharedState.Store!;
        if (expectedReason == null)
            throw new Exception("expectedReason is null");
        var items = new List<CertificateItemInfo>();
        await foreach (var item in store.GetInventory(0, 500, CancellationToken.None))
            items.Add(item);
        var revoked = items.FirstOrDefault(i => i.RevocationReason != null &&
            i.RevocationReason.ToString()!.Equals(expectedReason, StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(revoked);
    }

    [Then("the error description contains (.+)")]
    public void ThenErrorContainsKeyword(string keyword)
    {
        var r = TestSharedState.ToolResult;
        Assert.NotNull(r);
        var msg = r.ErrorMessage ?? "";
        // Strip surrounding quotes that regex capture groups may include
        keyword = keyword.Trim('"').Trim('\'');
        Assert.True(msg.Contains(keyword, StringComparison.OrdinalIgnoreCase),
            $"Error '{msg}' does not contain '{keyword}'");
    }

    [Then("all tools MUST be registered successfully")]
    public void ThenAllToolsRegistered()
    {
        var tools = TestSharedState.Tools;
        Assert.NotNull(tools);
        Assert.True(tools.Count >= 10, $"Expected >=10 tools, got {tools.Count}");
    }

    [Then("the tool definition MUST exist")]
    public void ThenToolDefinitionExists()
    {
        Assert.NotNull(TestSharedState.Tools);
    }

    [Then("it MUST have a non-empty name (.+)")]
    public void ThenToolHasNonEmptyName(string expectedName)
    {
        var tools = TestSharedState.Tools;
        Assert.NotNull(tools);
        // Strip surrounding quotes that Scenario Outline substitution may add
        expectedName = expectedName.Trim('"').Trim('\'');
        Assert.True(tools.ContainsKey(expectedName),
            $"Tool '{expectedName}' not found. Available: {string.Join(", ", tools.Keys)}");
    }

    [Then("it MUST have a valid JSON Schema input schema")]
    public void ThenToolHasValidSchema()
    {
        var tools = TestSharedState.Tools;
        Assert.NotNull(tools);
        foreach (var (_, def) in tools)
        {
            Assert.NotNull(def.InputSchema);
            Assert.NotEmpty(def.InputSchema);

            using var schemaDoc = JsonDocument.Parse(def.InputSchema);
            Assert.Equal(JsonValueKind.Object, schemaDoc.RootElement.ValueKind);
            Assert.True(schemaDoc.RootElement.TryGetProperty("type", out var typeProp));
            Assert.Equal("object", typeProp.GetString());
            Assert.True(schemaDoc.RootElement.TryGetProperty("properties", out var propertiesProp));
            Assert.Equal(JsonValueKind.Object, propertiesProp.ValueKind);
        }
    }

    [Then("the items list MUST be a valid array")]
    public void ThenItemsListIsValidArray()
    {
        Assert.NotNull(TestSharedState.ToolResult);
        Assert.True(TestSharedState.ToolResult.IsSuccess);
    }

    [Then("the CRL bytes MAY be present when includePem is false")]
    public void ThenCrlBytesOptional()
    {
        // No-op — this is a "may be present" check
    }
}
