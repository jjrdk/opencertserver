using Xunit;

namespace opencertserver.cli.tests.StepDefinitions
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using Reqnroll;

    [Binding]
    public partial class OpenCertServerCliStepDefinitions : IDisposable
    {
        private string? _output;
        private string? _tempKeyPath;
        private string? _tempOutPath;
        private string? _tempReenrollOutPath;

        [When("I run the CLI with \"(.*)\"")]
        public async Task WhenIRunTheCliWith(string arguments)
        {
            // support placeholders
            if (arguments.Contains("<GENERATE_KEY>"))
            {
                if (_tempKeyPath == null)
                {
                    using var rsa = RSA.Create(2048);
                    var pkcs8 = rsa.ExportPkcs8PrivateKey();
                    var pem = PemEncoding.WriteString("PRIVATE KEY", pkcs8);
                    _tempKeyPath = Path.Combine(Path.GetTempPath(), $"opencert_key_{Guid.NewGuid():N}.pem");
                    await File.WriteAllTextAsync(_tempKeyPath, pem);
                }

                arguments = arguments.Replace("<GENERATE_KEY>", _tempKeyPath);
            }

            if (arguments.Contains("<TEMP_OUT>"))
            {
                _tempOutPath ??= Path.Combine(Path.GetTempPath(), $"opencert_csr_{Guid.NewGuid():N}.pem");
                arguments = arguments.Replace("<TEMP_OUT>", _tempOutPath);
            }

            if (arguments.Contains("<TEMP_REENROLL_OUT>"))
            {
                _tempReenrollOutPath = Path.Combine(Path.GetTempPath(), $"opencert_reenroll_{Guid.NewGuid():N}.pem");
                arguments = arguments.Replace("<TEMP_REENROLL_OUT>", _tempReenrollOutPath);
            }

            // Call Program.Main in-process to avoid subprocess/environment differences.
            // Split on whitespace then recombine values for options so multi-word values (e.g., San Francisco)
            // are preserved even if quoting was lost by the test runner.
            var rawTokens = arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var args = RecombineOptionValues(rawTokens);
            Program.MessageHandlerFactory = () => _server.CreateHandler();
            await Program.Main(args);
            var swOut = new StringWriter();
            var swErr = new StringWriter();
            var origOut = Console.Out;
            var origErr = Console.Error;
            try
            {
                Console.SetOut(swOut);
                Console.SetError(swErr);
                await Program.Main(args);
            }
            finally
            {
                Console.SetOut(origOut);
                Console.SetError(origErr);
            }

            _output = $"{swOut}{swErr}";
        }

        private static string[] SplitArguments(string commandLine)
        {
            if (string.IsNullOrEmpty(commandLine)) return Array.Empty<string>();
            var args = new List<string>();
            var current = new System.Text.StringBuilder();
            var inQuotes = false;
            foreach (var c in commandLine)
            {
                if (c == '"')
                {
                    inQuotes = !inQuotes;
                    continue;
                }

                if (char.IsWhiteSpace(c) && !inQuotes)
                {
                    if (current.Length > 0)
                    {
                        args.Add(current.ToString());
                        current.Clear();
                    }
                }
                else
                {
                    current.Append(c);
                }
            }

            if (current.Length > 0) args.Add(current.ToString());
            return args.ToArray();
        }

        private static string[] RecombineOptionValues(string[] tokens)
        {
            var outArgs = new List<string>();
            var i = 0;
            while (i < tokens.Length)
            {
                var tok = tokens[i];
                if (tok.StartsWith("--"))
                {
                    // option key
                    var sb = new System.Text.StringBuilder();
                    outArgs.Add(tok);
                    i++;
                    // collect subsequent tokens that are values until next token that starts with --
                    while (i < tokens.Length && !tokens[i].StartsWith("--"))
                    {
                        if (sb.Length > 0) sb.Append(' ');
                        sb.Append(tokens[i]);
                        i++;
                    }

                    if (sb.Length > 0)
                    {
                        outArgs.Add(sb.ToString());
                    }
                }
                else
                {
                    // positional or stray token
                    outArgs.Add(tok);
                    i++;
                }
            }

            return outArgs.ToArray();
        }

        [Then("the output should contain \"(.*)\"")]
        public void ThenTheOutputShouldContain(string expected)
        {
            Assert.Contains(expected, _output);
        }

        [Then("the file \"(.*)\" should exist and contain CSR")]
        public void ThenTheFileShouldExistAndContainCsr(string path)
        {
            if (path == "<TEMP_OUT>")
            {
                path = _tempOutPath ?? path;
            }

            Assert.True(File.Exists(path), $"expected CSR file to exist at {path}");
            Assert.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", File.ReadAllText(path).Trim());
        }

        [Then("the certificate \"(.*)\" should exist")]
        public void ThenTheCertificateShouldExist(string path)
        {
            if (path == "<TEMP_OUT>")
            {
                path = _tempOutPath ?? path;
            }

            if (path == "<TEMP_REENROLL_OUT>")
            {
                path = _tempReenrollOutPath ?? path;
            }

            Assert.True(File.Exists(path), $"expected certificate to exist at {path}");
            Assert.StartsWith("-----BEGIN CERTIFICATE-----", File.ReadAllText(path).Trim());
        }
    }
}
