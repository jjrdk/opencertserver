namespace OpenCertServer.Build
{
    using Cake.Frosting;

    [TaskName("Default")]
    [IsDependentOn(typeof(PackTask))]
    public class DefaultTask : FrostingTask
    {
    }
}
