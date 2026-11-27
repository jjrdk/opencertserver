using Reqnroll;

namespace OpenCertServer.Iq.Tests.Support;

[Binding]
public sealed class IqRunHooks
{
    [AfterTestRun(Order = int.MaxValue)]
    public static void CleanArtifacts()
    {
        if (Directory.Exists(RepositoryPaths.IqArtifacts))
        {
            Directory.Delete(RepositoryPaths.IqArtifacts, true);
        }
    }
}
