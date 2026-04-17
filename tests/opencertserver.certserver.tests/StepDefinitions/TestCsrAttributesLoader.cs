using OpenCertServer.Est.Server.Response;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Claims;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509.Templates;
using OpenCertServer.Est.Server.Handlers;

internal static class TestCsrAttributesLoaderConfiguration
{
    private static Func<string?, ClaimsPrincipal?, CancellationToken, Task<CsrAttributesResponse>> _factory =
        static (_, _, _) => Task.FromResult(
            CsrAttributesResponse.FromTemplate(
                new CertificateSigningRequestTemplate(
                    subject: new NameTemplate(new RDNSequenceTemplate(
                    [
                        new RelativeDistinguishedNameTemplate([new SingleAttributeTemplate(Oids.CommonName.InitializeOid())])
                    ])),
                    subjectPkInfo: null)));

    public static void Reset()
    {
        _factory = static (_, _, _) => Task.FromResult(
            CsrAttributesResponse.FromTemplate(
                new CertificateSigningRequestTemplate(
                    subject: new NameTemplate(new RDNSequenceTemplate(
                    [
                        new RelativeDistinguishedNameTemplate([new SingleAttributeTemplate(Oids.CommonName.InitializeOid())])
                    ])),
                    subjectPkInfo: null)));
    }

    public static void SetFactory(Func<string?, ClaimsPrincipal?, CancellationToken, Task<CsrAttributesResponse>> factory)
    {
        _factory = factory;
    }

    public static Task<CsrAttributesResponse> GetTemplate(
        string? profileName,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
    {
        return _factory(profileName, user, cancellationToken);
    }
}

internal class TestCsrAttributesLoader : ICsrTemplateLoader
{
    public async Task<CsrAttributesResponse> GetTemplate(
        string? profileName,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
    {
        return await TestCsrAttributesLoaderConfiguration.GetTemplate(profileName, user, cancellationToken);
    }
}
