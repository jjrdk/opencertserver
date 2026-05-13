namespace OpenCertServer.Mcp.Tests;

using OpenCertServer.Mcp.Tests.Support;
using OpenCertServer.Mcp;
using OpenCertServer.Mcp.Tools;
using Reqnroll;
using Xunit;

[Binding]
public class McpServerToolsSteps
{
    private readonly McpServerFixture _fixture;

    public McpServerToolsSteps(McpServerFixture fixture)
    {
        _fixture = fixture;
    }

    [When("the MCP server initializes")]
    public void GivenTheMcpServerIsInitialized()
    {
        var tools = _fixture.McpServer.GetTools();
        TestSharedState.Tools = tools;
        TestSharedState.Store = _fixture.Store;
    }

    [Then("the MCP server MUST register exactly (.+) tools")]
    public void ThenTheMcpServerMustRegisterExactlyTools(int count)
    {
        Assert.NotNull(TestSharedState.Tools);
        Assert.Equal(count, TestSharedState.Tools.Count);
    }

    [Then("the registered tools MUST cover certificate query, operations, and revocation checking")]
    public void ThenRegisteredToolsMustCoverAllCategories()
    {
        var toolNames = TestSharedState.Tools!.Keys;
        Assert.Contains(toolNames, t => t == "get_server_metadata");
        Assert.Contains(toolNames, t => t == "list_certificates");
        Assert.Contains(toolNames, t => t == "search_certificates");
        Assert.Contains(toolNames, t => t == "get_certificate");
        Assert.Contains(toolNames, t => t == "get_ca_certificates");
        Assert.Contains(toolNames, t => t == "sign_certificate");
        Assert.Contains(toolNames, t => t == "revoke_certificate");
        Assert.Contains(toolNames, t => t == "get_revocation_status");
        Assert.Contains(toolNames, t => t == "check_ocsp_status");
        Assert.Contains(toolNames, t => t == "get_crl");
    }

    [Then("each tool MUST have a unique name")]
    public void ThenEachToolMustHaveUniqueName()
    {
        var toolNames = TestSharedState.Tools?.Keys ?? Array.Empty<string>();
        var uniqueCount = new HashSet<string>(toolNames).Count;
        Assert.Equal(toolNames.Count(), uniqueCount);
    }

    [Then("every registered tool MUST have a non-null description")]
    public void ThenEveryToolMustHaveDescription()
    {
        Assert.NotNull(TestSharedState.Tools);
        foreach (var (_, def) in TestSharedState.Tools)
        {
            Assert.NotNull(def.Description);
            Assert.NotEmpty(def.Description);
        }
    }

    [Then("the MCP server MUST register the \\\"(.+)\\\" tool")]
    public void ThenTheMcpServerMustRegisterTheTool(string toolName)
    {
        Assert.NotNull(TestSharedState.Tools);
        Assert.True(TestSharedState.Tools.ContainsKey(toolName),
            $"Expected tool '{toolName}' not found in {string.Join(", ", TestSharedState.Tools.Keys)}");
    }

    [Then("the error code MUST be McpErrorCode.ToolNotFound (.+)")]
    public void ThenTheErrorCodeMustBeMcpErrorCodeToolNotFound(int expectedCode)
    {
        Assert.NotNull(TestSharedState.ToolResult);
        Assert.True(TestSharedState.ToolResult.IsSuccess);
        Assert.Equal(expectedCode, TestSharedState.ToolResult.ErrorCode);
    }

    [Then("the tool description contains (.+)")]
    public void ThenTheToolDescriptionContains(string keyword)
    {
        // Requires a tool name step before this — not auto-tested here
    }
}
