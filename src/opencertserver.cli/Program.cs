// Program.cs for opencertserver.cli

using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Runtime.CompilerServices;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils; // for ToPkcs10 extension
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
            CreateCreateCsrCommand(rootCommand);
            CreateCsrFromKeysCommand(rootCommand);
            CreateSignCsrCommand(rootCommand);
            CreateEstEnrollCommand(rootCommand);

            // Add more commands as needed

            return await rootCommand.Parse(args).InvokeAsync();
        }
    }
}
