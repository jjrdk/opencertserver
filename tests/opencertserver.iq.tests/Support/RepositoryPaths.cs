namespace OpenCertServer.Iq.Tests.Support;

/// <summary>Locates the repository from the test assembly so the harness can publish and build images.</summary>
internal static class RepositoryPaths
{
    public static string Root { get; } = FindRoot();

    public static string IqProject => Path.Combine(Root, "tests", "opencertserver.iq.tests");

    public static string RunId { get; } = Guid.NewGuid().ToString("N");

    /// <summary>Run-isolated scratch space for publishes and Docker build contexts (git-ignored).</summary>
    public static string IqArtifacts { get; } = Path.Combine(Root, "artifacts", "iq", RunId);

    private static string FindRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "opencertserver.slnx")))
            {
                return dir.FullName;
            }
        }

        throw new InvalidOperationException("Could not locate the repository root (opencertserver.slnx).");
    }
}
