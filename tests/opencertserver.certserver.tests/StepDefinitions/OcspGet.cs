namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Ca.Utils;
using Ca.Utils.Ocsp;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    [When("an OCSP client sends a GET request using {string} with base64 special characters")]
    public async Task WhenAnOcspClientSendsAGetRequestWithBase64SpecialCharacters(string encoding)
    {
        var request = await BuildValidOcspRequestAsync().ConfigureAwait(false);
        string encoded = string.Empty;
        for (var nonceLength = 16; nonceLength <= 18; nonceLength++)
        {
            var nonce = new byte[nonceLength];
            Array.Fill(nonce, (byte)0xfb);
            var withNonce = new OcspRequest(new TbsRequest(
                requestList: request.TbsRequest.RequestList,
                requestExtensions: [new X509Extension(Oids.OcspNonce, nonce, false)]));
            encoded = Convert.ToBase64String(withNonce.GetBytes());
            if (encoded.EndsWith('='))
            {
                break;
            }
        }

        Assert.Contains("+", encoded);
        Assert.Contains("/", encoded);
        Assert.EndsWith("=", encoded);
        encoded = encoding switch
        {
            "url-encoded base64" => Uri.EscapeDataString(encoded),
            "base64" => encoded,
            "base64url" => encoded.Replace('+', '-').Replace('/', '_').TrimEnd('='),
            "padded base64url" => encoded.Replace('+', '-').Replace('/', '_'),
            _ => throw new ArgumentException($"Unsupported OCSP GET encoding: {encoding}", nameof(encoding))
        };
        await SendEncodedOcspGetAsync(encoded).ConfigureAwait(false);
    }

    [When("an OCSP client sends a GET request with invalid encoded data {string}")]
    public Task WhenAnOcspClientSendsAGetRequestWithInvalidEncodedData(string encoded)
        => SendEncodedOcspGetAsync(Uri.EscapeDataString(encoded));

    private async Task SendEncodedOcspGetAsync(string encoded)
    {
        using var client = _server.CreateClient();
        var response = await client.GetAsync($"ca/ocsp/{encoded}").ConfigureAwait(false);
        OcspState.LastHttpResponse = response;
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        OcspState.LastResponse = new OcspResponse(new AsnReader(bytes, AsnEncodingRules.DER));
    }
}
