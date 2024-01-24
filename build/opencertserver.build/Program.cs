namespace OpenCertServer.Build;

using System;
using Cake.Frosting;

public static class Program
{
    public static int Main(string[] args)
    {
        return new CakeHost()
            .InstallTool(new Uri("nuget:?package=GitVersion.Tool&version=5.12.0"))
            .UseContext<BuildContext>()
            .Run(args);
    }
}
