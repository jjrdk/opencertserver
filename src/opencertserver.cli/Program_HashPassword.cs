namespace opencertserver.cli;

using System;
using System.CommandLine;
using System.Threading.Tasks;
using OpenCertServer.Ca.Utils;

internal static partial class Program
{
    /// <summary>
    /// <c>hash-password</c>: the hash for Est:BasicAuth:Users. The password is read from standard
    /// input, never from the command line, where it would show in the process list and the shell
    /// history: <c>printf '%s' 'secret' | opencert hash-password</c>.
    /// </summary>
    private static void CreateHashPasswordCommand(RootCommand rootCommand)
    {
        var iterationsOption = new Option<int>("--iterations")
        {
            Description = "PBKDF2 rounds",
            DefaultValueFactory = _ => PasswordHash.DefaultIterations
        };

        var cmd = new Command("hash-password", "Hash a password for EST Basic authentication (read from stdin)")
        {
            iterationsOption
        };

        cmd.SetAction(parse =>
        {
            var password = Console.In.ReadToEnd().TrimEnd('\r', '\n');
            if (password.Length == 0)
            {
                Console.Error.WriteLine("No password on standard input.");
                return Task.FromResult(1);
            }

            Console.WriteLine(PasswordHash.Create(password, parse.GetValue(iterationsOption)));
            return Task.FromResult(0);
        });

        rootCommand.Subcommands.Add(cmd);
    }
}
