namespace OpenCertServer.Iq.Tests.StepDefinitions;

using DotNet.Testcontainers.Containers;

/// <summary>Per-scenario state shared by the ACME IQ step definitions and hooks.</summary>
public sealed class AcmeScenarioState
{
    /// <summary>A per-scenario working directory inside the client container (acme.sh config home, raw-client state).</summary>
    public string WorkDir { get; } = $"/work/{Guid.NewGuid():N}";

    public ExecResult? LastExec { get; set; }

    public int? Status { get; set; }

    public string Headers { get; set; } = "";

    /// <summary>Path of the last response body inside the client container.</summary>
    public string BodyPath { get; set; } = "";

    public string? Domain { get; set; }

    /// <summary>The ACME client that obtained <see cref="Domain"/>'s certificate: <c>acme.sh</c> or <c>certbot</c>.</summary>
    public string AcmeClient { get; set; } = "acme.sh";

    public string? Serial { get; set; }

    /// <summary>The directory URL the raw client talks to (the TOS scenario uses a dedicated server).</summary>
    public string? DirectoryUrl { get; set; }

    public IContainer? TosServer { get; set; }
}
