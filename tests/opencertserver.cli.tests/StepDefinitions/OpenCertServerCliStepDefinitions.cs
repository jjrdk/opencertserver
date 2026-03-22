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
        private static readonly System.Threading.SemaphoreSlim CliExecutionLock = new(1, 1);

        private string? _output;
        private string? _tempKeyPath;
        private string? _tempOutPath;
        private string? _tempReenrollOutPath;
        private string? _tempKeyPrefix;
        private string? _tempPrivateKeyOutPath;
        private string? _tempPublicKeyOutPath;

        [When("I run the CLI with \"(.*)\"")]
        public async Task WhenIRunTheCliWith(string arguments)
        {
            await CliExecutionLock.WaitAsync();

            // support placeholders
            try
            {
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
                    _tempReenrollOutPath =
                        Path.Combine(Path.GetTempPath(), $"opencert_reenroll_{Guid.NewGuid():N}.pem");
                    arguments = arguments.Replace("<TEMP_REENROLL_OUT>", _tempReenrollOutPath);
                }

                if (arguments.Contains("<TEMP_PRIVATE_KEY>") || arguments.Contains("<TEMP_PUBLIC_KEY>"))
                {
                    var keyDirectory = Path.Combine(Path.GetTempPath(), $"opencert_keys_{Guid.NewGuid():N}");
                    _tempPrivateKeyOutPath ??= Path.Combine(keyDirectory, "private-key.pem");
                    _tempPublicKeyOutPath ??= Path.Combine(keyDirectory, "public-key.pem");
                    arguments = arguments.Replace("<TEMP_PRIVATE_KEY>", _tempPrivateKeyOutPath);
                    arguments = arguments.Replace("<TEMP_PUBLIC_KEY>", _tempPublicKeyOutPath);
                }

                if (arguments.Contains("<TEMP_KEY_PREFIX>"))
                {
                    var keyDirectory = Path.Combine(Path.GetTempPath(), $"opencert_out_{Guid.NewGuid():N}");
                    _tempKeyPrefix ??= Path.Combine(keyDirectory, "generated-key");
                    _tempPrivateKeyOutPath ??= $"{_tempKeyPrefix}-private.pem";
                    _tempPublicKeyOutPath ??= $"{_tempKeyPrefix}-public.pem";
                    arguments = arguments.Replace("<TEMP_KEY_PREFIX>", _tempKeyPrefix);
                }

                // Call Program.Main in-process to avoid subprocess/environment differences.
                // Split on whitespace then recombine values for options so multi-word values (e.g., San Francisco)
                // are preserved even if quoting was lost by the test runner.
                var rawTokens = arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var args = RecombineOptionValues(rawTokens);
                if (_server != null)
                {
                    Program.MessageHandlerFactory = () => _server.CreateHandler();
                }

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
            finally
            {
                CliExecutionLock.Release();
            }
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
            path = ResolvePlaceholder(path);

            Assert.True(File.Exists(path), $"expected CSR file to exist at {path}");
            Assert.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", File.ReadAllText(path).Trim());
        }

        [Then("the certificate \"(.*)\" should exist")]
        public void ThenTheCertificateShouldExist(string path)
        {
            path = ResolvePlaceholder(path);

            Assert.True(File.Exists(path), $"expected certificate to exist at {path}");
            Assert.StartsWith("-----BEGIN CERTIFICATE-----", File.ReadAllText(path).Trim());
        }

        [Then("the generated \"(.*)\" key files \"(.*)\" and \"(.*)\" should exist and match")]
        public void ThenTheGeneratedKeyFilesShouldExistAndMatch(string algorithm, string privatePath, string publicPath)
        {
            privatePath = ResolvePlaceholder(privatePath);
            publicPath = ResolvePlaceholder(publicPath);

            Assert.True(File.Exists(privatePath), $"expected private key file to exist at {privatePath}");
            Assert.True(File.Exists(publicPath), $"expected public key file to exist at {publicPath}");

            var privatePem = File.ReadAllText(privatePath).Trim();
            var publicPem = File.ReadAllText(publicPath).Trim();

            Assert.StartsWith("-----BEGIN PRIVATE KEY-----", privatePem);
            Assert.StartsWith("-----BEGIN PUBLIC KEY-----", publicPem);

            switch (algorithm.Trim().ToLowerInvariant())
            {
                case "rsa":
                    using (var privateKey = RSA.Create())
                    {
                        using var publicKey = RSA.Create();
                        publicKey.ImportFromPem(publicPem);
                        privateKey.ImportFromPem(privatePem);
                        Assert.Equal(privateKey.ExportSubjectPublicKeyInfo(), publicKey.ExportSubjectPublicKeyInfo());
                    }

                    break;
                case "ecdsa":
                    using (var privateKey = ECDsa.Create())
                    {
                        using var publicKey = ECDsa.Create();
                        publicKey.ImportFromPem(publicPem);
                        privateKey.ImportFromPem(privatePem);
                        Assert.Equal(privateKey.ExportSubjectPublicKeyInfo(), publicKey.ExportSubjectPublicKeyInfo());
                    }

                    break;
                case "mldsa":
                {
#pragma warning disable SYSLIB5006
                    var privateKey = MLDsa.ImportFromPem(privatePem);
                    var publicKey = MLDsa.ImportFromPem(publicPem);

                    Assert.Equal(privateKey.ExportSubjectPublicKeyInfo(), publicKey.ExportSubjectPublicKeyInfo());
#pragma warning restore SYSLIB5006
                }
                    break;
                default:
                    throw new InvalidOperationException($"Unsupported algorithm '{algorithm}' in test assertion.");
            }
        }

        private string ResolvePlaceholder(string path)
        {
            return path switch
            {
                "<TEMP_OUT>" => _tempOutPath ?? path,
                "<TEMP_REENROLL_OUT>" => _tempReenrollOutPath ?? path,
                "<TEMP_KEY_PREFIX>" => _tempKeyPrefix ?? path,
                "<TEMP_PRIVATE_KEY>" => _tempPrivateKeyOutPath ?? path,
                "<TEMP_PUBLIC_KEY>" => _tempPublicKeyOutPath ?? path,
                _ => path
            };
        }
    }
}
