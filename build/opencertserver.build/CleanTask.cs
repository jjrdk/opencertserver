namespace OpenCertServer.Build
{
    using Cake.Common.IO;
    using Cake.Core.Diagnostics;
    using Cake.Core.IO;
    using Cake.Frosting;

    [TaskName("Clean")]
    [IsDependentOn(typeof(VersionTask))]
    public sealed class CleanTask : FrostingTask<BuildContext>
    {
        public override void Run(BuildContext context)
        {
            context.Log.Information("Clean bin folders");
            context.CleanDirectories(new GlobPattern("/src/**/bin" + context.BuildConfiguration));
            context.CleanDirectories(new GlobPattern("/tests/**/bin" + context.BuildConfiguration));

            context.Log.Information("Clean obj folders");
            context.CleanDirectories("/src/**/obj" + context.BuildConfiguration);
            context.CleanDirectories("/tests/**/obj" + context.BuildConfiguration);

            context.Log.Information("Clean old build artifacts");
            context.CleanDirectories("/artifacts/publish");
        }
    }
}
