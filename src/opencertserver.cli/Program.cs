// Program.cs for opencertserver.cli

using System;
using System.CommandLine;
using System.Net.Http;
using System.Runtime.CompilerServices;
// for ToPkcs10 extension
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("opencertserver.cli.tests")]

namespace opencertserver.cli
{
    internal static partial class Program
    {
        public static async Task<int> Main(string[] args)
        {
            var rootCommand = new RootCommand("OpenCertServer CLI - Certificate Authority Tools");

            CreatePrintCertificateCommand(rootCommand);
            CreateGenerateKeysCommand(rootCommand);
            CreateCreateCsrCommand(rootCommand);
            CreateCsrFromKeysCommand(rootCommand);
            CreateSignCsrCommand(rootCommand);
            CreateEstEnrollCommand(rootCommand);
            CreateEstReEnrollCommand(rootCommand);
            CreateEstServerCertificatesCommand(rootCommand);

            // Add more commands as needed

            return await rootCommand.Parse(args).InvokeAsync();
        }

        internal static Func<HttpMessageHandler> MessageHandlerFactory { get; set; } = () => new HttpClientHandler();
    }
}
