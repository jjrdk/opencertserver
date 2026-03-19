namespace OpenCertServer.Build;

using Cake.Frosting;

[TaskName("Default")]
[IsDependentOn(typeof(CliPublishTask))]
public sealed class DefaultTask : FrostingTask
{
    // Deliberately empty
}
