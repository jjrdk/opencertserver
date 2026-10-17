namespace OpenCertServer.Est.Tests.Steps;

using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Pkcs7;
using Reqnroll;
using Xunit;

/// <summary>Steps for <c>EstBasicAuthentication.feature</c>.</summary>
public partial class EstServer
{
    [Given("""^a certificate server where the user "([^"]+)" has the password "([^"]+)"$""")]
    public async Task GivenACertificateServerWhereTheUserHasThePassword(string userName, string password)
    {
        _context[nameof(BasicUsers)] = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [userName] = PasswordHash.Create(password, iterations: 10_000) // fewer rounds: a test, not a server
        };
        await GivenACertificateServerThatCompliesWithEstRfc().ConfigureAwait(false);
    }

    [Given("a certificate server whose Basic users file cannot be read")]
    public async Task GivenACertificateServerWhoseBasicUsersFileCannotBeRead()
    {
        // The file exists and the process may not read it - the case of a wrong owner or mode on
        // a server. A directory in its place would not do: FileInfo.Exists is false for one. Only
        // a Unix mode can express it, and root reads anything, so elsewhere the scenario is skipped.
        if (OperatingSystem.IsWindows())
        {
            Assert.Skip("An unreadable file needs a Unix file mode.");
            return;
        }

        if (Environment.IsPrivilegedProcess)
        {
            Assert.Skip("root can read a file with mode 000 - run the tests as an ordinary user.");
            return;
        }

        var path = Path.Combine(Directory.CreateTempSubdirectory("est-users-").FullName, "users");
        await File.WriteAllTextAsync(path, "vpn.example.org:pbkdf2-sha256$1$AA$AA\n").ConfigureAwait(false);
        File.SetUnixFileMode(path, UnixFileMode.None);
        _context[nameof(BasicUsersFile)] = path;
        await GivenACertificateServerThatCompliesWithEstRfc().ConfigureAwait(false);
    }

    [When("""^the client "([^"]+)" with the password "([^"]+)" submits a rsa CSR for "([^"]+)"$""")]
    public async Task WhenTheClientWithThePasswordSubmitsACsr(string userName, string password, string subject)
    {
        using var rsa = RSA.Create();
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

        using var handler = _server.CreateHandler();
        using var httpClient = new HttpClient(handler);
        var message = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri("https://localhost/.well-known/est/rsa/simpleenroll"),
            Content = new StringContent(request.ToPkcs10Base64(), Encoding.UTF8, "application/pkcs10")
        };
        message.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{userName}:{password}")));

        var response = await httpClient.SendAsync(message).ConfigureAwait(false);
        _context["basicResponse"] = response;
        if (response.IsSuccessStatusCode)
        {
            var bytes = (await response.Content.ReadAsStringAsync().ConfigureAwait(false)).Base64DecodeBytes();
            var contentInfo = new CmsContentInfo(new System.Formats.Asn1.AsnReader(bytes, System.Formats.Asn1.AsnEncodingRules.DER));
            var signedData = new SignedData(new System.Formats.Asn1.AsnReader(contentInfo.EncodedContent, System.Formats.Asn1.AsnEncodingRules.DER));
            _context["enrolledCertificate"] = new X509Certificate2Collection(signedData.Certificates ?? []);
            _context["errorMessage"] = null;
        }
        else
        {
            _context["enrolledCertificate"] = null;
            _context["errorMessage"] = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }
    }

    [Then("the server answers 401 and challenges with Basic")]
    public void ThenTheServerAnswers401AndChallengesWithBasic()
    {
        var response = (HttpResponseMessage)_context["basicResponse"]!;
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == "Basic");
    }

    [Then("the server answers 401 without a Basic challenge")]
    public void ThenTheServerAnswers401WithoutABasicChallenge()
    {
        var response = (HttpResponseMessage)_context["basicResponse"]!;
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain(response.Headers.WwwAuthenticate, h => h.Scheme == "Basic");
    }

    [When("""^the password "([^"]+)" is hashed$""")]
    public void WhenThePasswordIsHashed(string password)
    {
        _context["passwordHash"] = PasswordHash.Create(password, iterations: 10_000);
    }

    [Then("""^the hash verifies "([^"]+)" and refuses "([^"]+)"$""")]
    public void ThenTheHashVerifiesAndRefuses(string right, string wrong)
    {
        var hash = (string)_context["passwordHash"]!;
        Assert.True(PasswordHash.Verify(right, hash));
        Assert.False(PasswordHash.Verify(wrong, hash));
        Assert.False(PasswordHash.Verify(right, "not-a-hash"));
    }

    [Then("""^the hash starts with "([^"]+)"$""")]
    public void ThenTheHashStartsWith(string prefix)
    {
        Assert.StartsWith(prefix, (string)_context["passwordHash"]!, StringComparison.Ordinal);
    }
}
