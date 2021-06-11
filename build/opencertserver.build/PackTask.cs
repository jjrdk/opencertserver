namespace OpenCertServer.Build
{
    using Cake.Common.Tools.DotNetCore;
    using Cake.Common.Tools.DotNetCore.MSBuild;
    using Cake.Common.Tools.DotNetCore.Pack;
    using Cake.Core.Diagnostics;
    using Cake.Frosting;

    [TaskName("Pack")]
    [IsDependentOn(typeof(TestsTask))]
    public class PackTask : FrostingTask<BuildContext>
    {
        /// <inheritdoc />
        public override void Run(BuildContext context)
        {
            context.Log.Information("Package version: " + context.BuildVersion);

            var packSettings = new DotNetCorePackSettings
            {
                Configuration = context.BuildConfiguration,
                NoBuild = true,
                NoRestore = true,
                OutputDirectory = "./artifacts/packages",
                IncludeSymbols = true,
                MSBuildSettings = new DotNetCoreMSBuildSettings().SetConfiguration(context.BuildConfiguration)
                    .SetVersion(context.BuildVersion)
            };

            context.DotNetCorePack("./src/opencertserver.est.client/opencertserver.est.client.csproj", packSettings);
            context.DotNetCorePack("./src/opencertserver.ca.utils/opencertserver.ca.utils.csproj", packSettings);
        }
    }
}
