namespace OpenCertServer.Build
{
    using System.Linq;
    using Cake.Core;
    using Cake.Frosting;

    public class BuildContext : FrostingContext
    {
        public string BuildConfiguration { get; set; }
        public string BuildVersion { get; set; } = "0.0.1";
        public string InformationalVersion { get; set; } = "0.0.1";

        public string SolutionName = "opencertserver.sln";

        public BuildContext(ICakeContext context)
            : base(context)
        {
            Environment.WorkingDirectory = Environment.WorkingDirectory.Combine("..").Combine("..").Collapse();
            BuildConfiguration = context.Arguments.GetArguments("configuration").FirstOrDefault() ?? "Debug";
        }
    }
}
