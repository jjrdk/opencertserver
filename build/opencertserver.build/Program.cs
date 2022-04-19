namespace OpenCertServer.Build
{
    using System;
    using Cake.Frosting;

    public static class Program
    {
        public static int Main(string[] args)
        {
            return new CakeHost()
                .InstallTool(new Uri("nuget:?package=GitVersion.CommandLine&version=5.6.7"))
                //.InstallTool(new Uri("nuget:?package=Cake.Docker&version=1.0.0"))
                .UseContext<BuildContext>()
                .Run(args);
        }
    }
}