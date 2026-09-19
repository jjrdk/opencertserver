// Program.cs for opencertserver.cli
// for ToPkcs10 extension

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("opencertserver.cli.tests")]

namespace opencertserver.cli
{
    using System;
    using System.CommandLine;
    using System.Net.Http;
    using System.Threading.Tasks;

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

            return await rootCommand.Parse(args).InvokeAsync().ConfigureAwait(false);
        }

        internal static Func<HttpMessageHandler> MessageHandlerFactory { get; set; } = () => new HttpClientHandler();
    }
}
