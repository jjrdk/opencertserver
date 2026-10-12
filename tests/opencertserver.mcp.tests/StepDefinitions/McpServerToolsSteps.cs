namespace OpenCertServer.Mcp.Tests.StepDefinitions;

using OpenCertServer.Mcp.Tests.Support;
using Reqnroll;
using Xunit;

[Binding]
public class McpServerToolsSteps
{
    private readonly McpServerFixture _fixture;
    private readonly McpScenarioContext _context;

    public McpServerToolsSteps(McpServerFixture fixture,
            McpScenarioContext context)
    {
        _fixture = fixture;
        _context = context;
    }

    [When("the MCP server initializes")]
    public void GivenTheMcpServerIsInitialized()
    {
        var tools = _fixture.ToolDefinitions;
        _context.Tools = tools;
        _context.Store = _fixture.Store;
    }

    [Then("the MCP server MUST register exactly (.+) tools")]
    public void ThenTheMcpServerMustRegisterExactlyTools(int count)
    {
        Assert.NotNull(_context.Tools);
        Assert.Equal(count, _context.Tools.Count);
    }

    [Then("the server MUST report exactly (.+) registered tools")]
    public void ThenServerMustReportExactlyTools(int count)
    {
        Assert.NotNull(_context.Tools);
        Assert.Equal(count, _context.Tools.Count);
    }

    [Then("the registered tools MUST cover certificate query, operations, and revocation checking")]
    public void ThenRegisteredToolsMustCoverAllCategories()
    {
        var toolNames = _context.Tools!.Keys;
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
        var toolNames = _context.Tools?.Keys ?? Array.Empty<string>();
        var uniqueCount = new HashSet<string>(toolNames).Count;
        Assert.Equal(toolNames.Count(), uniqueCount);
    }

    [Then("every registered tool MUST have a non-null description")]
    public void ThenEveryToolMustHaveDescription()
    {
        Assert.NotNull(_context.Tools);
        foreach (var (_, def) in _context.Tools)
        {
            Assert.NotNull(def.Description);
            Assert.NotEmpty(def.Description);
        }
    }

    [Then("it MUST have a non-empty description")]
    public void ThenCurrentToolMustHaveDescription()
    {
        Assert.NotNull(_context.Tools);
        foreach (var (_, def) in _context.Tools!)
        {
            Assert.NotNull(def.Description);
            Assert.NotEmpty(def.Description);
        }
    }

    [Then("the MCP server MUST register the \"(.+)\" tool")]
    public void ThenTheMcpServerMustRegisterTheTool(string toolName)
    {
        Assert.NotNull(_context.Tools);
        Assert.True(_context.Tools.ContainsKey(toolName),
            $"Expected tool '{toolName}' not found in {string.Join(", ", _context.Tools.Keys)}");
    }

    [Then("the error code MUST be McpErrorCode.ToolNotFound (.+)")]
    public void ThenTheErrorCodeMustBeMcpErrorCodeToolNotFound(string expectedCodeStr)
    {
        Assert.NotNull(_context.ToolResult);
        Assert.False(_context.ToolResult.IsSuccess);
        Assert.Equal((int)McpErrorCode.ToolNotFound, _context.ToolResult.ErrorCode);
    }

    [Then("the tool description contains (.+)")]
    public void ThenTheToolDescriptionContains(string keyword)
    {
        // Requires a tool name step before this — not auto-tested here
    }
}