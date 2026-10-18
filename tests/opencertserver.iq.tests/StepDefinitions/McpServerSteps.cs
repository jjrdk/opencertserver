namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Text.Json;
using DotNet.Testcontainers.Images;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Qualifies the standalone MCP executable through JSON-RPC and Linux OpenSSL.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class McpServerSteps(FeatureContext featureContext, ScenarioContext scenarioContext, IReqnrollOutputHelper output)
{
    public const string FeatureTitle = "The MCP server exposes the CA over stdio and fails closed";
    private IqMcpEnvironment _environment = null!;
    private bool _clientStarted;
    private JsonElement _response;

    [BeforeFeature]
    public static async Task PublishHost(FeatureContext context)
    {
        var directory = Path.Combine(RepositoryPaths.IqArtifacts, "mcp");
        await IqImages.PublishMcpAsync(directory).ConfigureAwait(false);
        context.Set(directory, "McpPublishDirectory");
        context.Set(await IqImages.GetClientAsync().ConfigureAwait(false));
    }

    [BeforeScenario]
    public async Task StartClient()
    {
        _environment = new IqMcpEnvironment(
            featureContext.Get<IImage>(), featureContext.Get<string>("McpPublishDirectory"));
        await _environment.StartAsync().ConfigureAwait(false);
        _clientStarted = true;
    }

    [AfterScenario]
    public async Task StopClient()
    {
        if (_environment is null)
        {
            return;
        }

        try
        {
            if (!_clientStarted)
            {
                return;
            }

            if (scenarioContext.TestError is not null)
            {
                output.WriteLine(await _environment.GetDiagnosticsAsync().ConfigureAwait(false));
            }

            await _environment.ControlAsync(new { action = "stop" }).ConfigureAwait(false);
        }
        finally
        {
            await _environment.DisposeAsync().ConfigureAwait(false);
        }
    }

    [Given("^the Linux client launches the MCP server over stdio in read-only mode$")]
    public Task LaunchReadOnly() => Launch("default");

    [Given("^the Linux client launches the MCP server with CA operations enabled and a configured \"McpServer:AuthenticationToken\"$")]
    public Task LaunchWithCa() => Launch("enabled");

    [Given("^the Linux client launches the MCP server with \"McpServer:EnableCaOperations\" = false$")]
    public Task LaunchDisabled() => Launch("disabled");

    [Given("^the Linux client launches the MCP server with \"McpServer:EnableCaOperations\" = true and no \"McpServer:AuthenticationToken\"$")]
    public Task LaunchWithoutToken() => Launch("missing-token");

    [Given("^the Linux client sends a \"tools/list\" JSON-RPC request on stdin$")]
    public async Task ListTools() =>
        _response = await Request("tools/list", new { }).ConfigureAwait(false);

    [Then("^the response lists the CA tools including \"get_server_metadata\" and \"get_crl\"$")]
    public void AssertTools()
    {
        var names = _response.GetProperty("result").GetProperty("tools").EnumerateArray()
            .Select(tool => tool.GetProperty("name").GetString()).ToArray();
        foreach (var name in new[]
                 {
                     "get_server_metadata", "list_certificates", "search_certificates", "get_certificate",
                     "get_ca_certificates", "get_revocation_status", "check_ocsp_status", "get_crl"
                 })
        {
            Assert.Contains(name, names);
        }

        Assert.DoesNotContain("sign_certificate", names);
        Assert.DoesNotContain("revoke_certificate", names);
    }

    [When("^the Linux client invokes \"(get_crl|sign_certificate)\" via JSON-RPC$")]
    public async Task InvokeTool(string tool)
    {
        if (tool == "sign_certificate")
        {
            await ListTools().ConfigureAwait(false);
            AssertTools();
        }

        _response = await Request("tools/call", new { name = tool, arguments = new { includePem = true } })
            .ConfigureAwait(false);
    }

    [Then("^the response carries a CRL$")]
    public async Task AssertCrl()
    {
        var data = ToolData(_response);
        var crl = data.GetProperty("crlBytesBase64").GetString();
        Assert.False(string.IsNullOrWhiteSpace(crl));
        await WriteBase64("ca.crl", crl!).ConfigureAwait(false);
        await FetchCa().ConfigureAwait(false);
        var verification = await Run(
            "openssl crl -inform DER -in ca.crl -noout -text -verify -CAfile ca.pem 2>&1").ConfigureAwait(false);
        Assert.Contains("verify OK", verification, StringComparison.Ordinal);
        Assert.Contains("Certificate Revocation List (CRL)", verification, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(data.GetProperty("issuer").GetString()));
        Assert.True(data.GetProperty("nextUpdate").GetDateTimeOffset() > DateTimeOffset.UtcNow);
    }

    [Then("^the JSON-RPC result is an error with code -32602 \\(\"unknown tool\"\\)$")]
    public void AssertToolNotFound()
    {
        Assert.Equal(-32602, _response.GetProperty("error").GetProperty("code").GetInt32());
        Assert.Equal("Unknown tool: 'sign_certificate'", _response.GetProperty("error").GetProperty("message").GetString());
    }

    [Then("^the process refuses to start and reports that an authentication token is required$")]
    public void AssertStartupRefused()
    {
        Assert.NotEqual(0, _response.GetProperty("exitCode").GetInt32());
        Assert.Equal("", _response.GetProperty("stdout").GetString());
        var error = _response.GetProperty("stderr").GetString();
        Assert.Contains("McpServer:AuthenticationToken is not set", error);
        Assert.Contains("server will not start", error);
    }

    [When("^the Linux client invokes \"sign_certificate\" with a valid CSR via JSON-RPC$")]
    public async Task SignCertificate()
    {
        await Run("openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr "
            + "-subj '/CN=mcp-caller' -addext 'subjectAltName=DNS:mcp-caller'").ConfigureAwait(false);
        var csr = await Run("cat client.csr").ConfigureAwait(false);
        _response = await Request("tools/call",
            new { name = "sign_certificate", arguments = new { csr, includePem = true } }).ConfigureAwait(false);
    }

    [Then("^the response contains a signed certificate$")]
    public async Task AssertSignedCertificate()
    {
        var data = ToolData(_response);
        var pem = data.GetProperty("pem").GetString();
        Assert.Contains("-----BEGIN CERTIFICATE-----", pem);
        await WriteBase64("client.pem", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(pem!)))
            .ConfigureAwait(false);
        await FetchCa().ConfigureAwait(false);
        await Run("openssl verify -CAfile ca.pem -verify_hostname mcp-caller client.pem "
            + "&& openssl x509 -in client.pem -pubkey -noout > cert.pub "
            + "&& openssl pkey -in client.key -pubout > key.pub && cmp cert.pub key.pub").ConfigureAwait(false);
        var serial = await Run("openssl x509 -in client.pem -noout -serial").ConfigureAwait(false);
        Assert.Equal(data.GetProperty("serialNumber").GetString()!.TrimStart('0'),
            serial.Trim()["serial=".Length..].TrimStart('0'), ignoreCase: true);
    }

    private async Task Launch(string mode) =>
        _response = await _environment.ControlAsync(new { action = "start", mode }).ConfigureAwait(false);

    private Task<JsonElement> Request(string method, object parameters) =>
        _environment.ControlAsync(new { action = "request", method, @params = parameters });

    private static JsonElement ToolData(JsonElement response)
    {
        Assert.False(response.TryGetProperty("error", out _), response.ToString());
        var result = response.GetProperty("result");
        Assert.False(result.TryGetProperty("isError", out var error) && error.GetBoolean(), result.ToString());
        var text = result.GetProperty("content").EnumerateArray()
            .Single(content => content.GetProperty("type").GetString() == "text").GetProperty("text").GetString();
        using var document = JsonDocument.Parse(text!);
        return document.RootElement.Clone();
    }

    private async Task FetchCa()
    {
        var response = await Request("tools/call", new { name = "get_ca_certificates", arguments = new { } })
            .ConfigureAwait(false);
        var certificates = ToolData(response).GetProperty("certificates").EnumerateArray()
            .Select(cert => cert.GetProperty("pem").GetString());
        var pem = string.Join("\n", certificates);
        Assert.Contains("-----BEGIN CERTIFICATE-----", pem);
        await WriteBase64("ca.pem", Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(pem)))
            .ConfigureAwait(false);
    }

    private Task<string> WriteBase64(string path, string content) =>
        Run($"printf '%s' '{content}' | base64 -d > '{path}'");

    private async Task<string> Run(string script)
    {
        var result = await _environment.ExecAsync(script).ConfigureAwait(false);
        Assert.True(result.ExitCode == 0, $"`{script}` exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}");
        return result.Stdout;
    }
}
