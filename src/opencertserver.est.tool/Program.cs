namespace OpenCertServer.Est.Cli;

using CommandLine;

internal static partial class Program
{
    private static async Task Main(string[] args)
    {
        var parser = new Parser(
            settings =>
            {
                settings.AutoHelp = true;
                settings.AutoVersion = true;
                settings.CaseInsensitiveEnumValues = true;
                settings.CaseSensitive = false;
                settings.EnableDashDash = true;
                settings.GetoptMode = false;
                settings.HelpWriter = Console.Out;
                settings.IgnoreUnknownArguments = true;
                settings.MaximumDisplayWidth = 80;
                settings.PosixlyCorrect = true;
            });

        await parser.ParseArguments<EnrollArgs, ReEnrollArgs, ConfigureArgs>(args)
            .MapResult(
                (EnrollArgs enrollArgs) => Enroll(enrollArgs),
                (ReEnrollArgs reEnrollArgs) => ReEnroll(reEnrollArgs),
                (ConfigureArgs configureArgs) => Configure(configureArgs),
                _ => Task.CompletedTask).ConfigureAwait(false);
    }
}
