namespace OpenCertServer.Build
{
    using Cake.Common.Tools.DotNet;
    using Cake.Frosting;

    [TaskName("Restore-Nuget-Packages")]
    [IsDependentOn(typeof(CleanTask))]
    public class RestoreNugetPackagesTask : FrostingTask<BuildContext>
    {
        /// <inheritdoc />
        public override void Run(BuildContext context)
        {
            context.DotNetRestore(context.SolutionName);
        }
    }
}