namespace OpenCertServer.Est.Cli;

using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Client;

internal static partial class Program
{
    private static async Task Enroll(EnrollArgs enrollArgs)
    {
        var config = await LoadConfig();
        using var client = new EstClient(new Uri(config.Server));
        var distinguishedName = new X500DistinguishedName(enrollArgs.DistinguishedName);

        X509Certificate2Collection? certs = null;
        var keyFileContent = await File.ReadAllTextAsync(enrollArgs.KeyFilePath).ConfigureAwait(false);
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(keyFileContent);
            certs = await RequestCertificate(enrollArgs, client, distinguishedName, rsa);
        }
        catch
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(keyFileContent);
            certs = await RequestCertificate(enrollArgs, client, distinguishedName, ecdsa);
        }
        finally
        {
            if (certs != null)
            {
                var pem = certs.ExportCertificatePems();
                await Console.Out.WriteLineAsync(pem).ConfigureAwait(false);
                if (enrollArgs.Output != null)
                {
                    await File.WriteAllTextAsync(enrollArgs.Output, pem).ConfigureAwait(false);
                }
            }
        }
    }

    private static async Task<X509Certificate2Collection> RequestCertificate(
        EnrollArgs enrollArgs,
        EstClient client,
        X500DistinguishedName distinguishedName,
        RSA rsa)
    {
        var (error, collection) = await client.Enroll(
            distinguishedName,
            rsa,
            enrollArgs.UsageFlags,
            new AuthenticationHeaderValue(enrollArgs.AuthenticationType, enrollArgs.AccessToken));
        if (error == null)
        {
            return collection!;
        }

        await Console.Error.WriteLineAsync($"Error enrolling certificate: {error}").ConfigureAwait(false);
        Environment.Exit(1);

        return collection!;
    }

    private static async Task<X509Certificate2Collection> RequestCertificate(
        EnrollArgs enrollArgs,
        EstClient client,
        X500DistinguishedName distinguishedName,
        ECDsa ecDsa)
    {
        var (error, collection) = await client.Enroll(
            distinguishedName,
            ecDsa,
            enrollArgs.UsageFlags,
            new AuthenticationHeaderValue(enrollArgs.AuthenticationType, enrollArgs.AccessToken));

        if (error == null)
        {
            return collection!;
        }

        await Console.Error.WriteLineAsync($"Error enrolling certificate: {error}").ConfigureAwait(false);
        Environment.Exit(1);

        return collection!;
    }
}
