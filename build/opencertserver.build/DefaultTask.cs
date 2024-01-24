namespace OpenCertServer.Build;

using Cake.Frosting;

[TaskName("Default")]
[IsDependentOn(typeof(LinuxDockerBuildTask))]
public sealed class DefaultTask : FrostingTask
{
    // Deliberately empty
}
