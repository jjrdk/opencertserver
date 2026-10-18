namespace OpenCertServer.Iq.Tests.Support;

/// <summary>Locates the repository from the test assembly so the harness can publish and build images.</summary>
internal static class RepositoryPaths
{
    public static string Root { get; } = FindRoot();

    public static string IqProject => Path.Combine(Root, "tests", "opencertserver.iq.tests");

    /// <summary>Scratch space for publish output and docker build contexts (git-ignored).</summary>
    public static string IqArtifacts => Path.Combine(Root, "artifacts", "iq");

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
