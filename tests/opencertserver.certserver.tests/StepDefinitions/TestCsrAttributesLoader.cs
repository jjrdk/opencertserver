namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Claims;
using OpenCertServer.Ca.Utils.X509.Templates;
using OpenCertServer.Est.Server.Handlers;

internal static class TestCsrAttributesLoaderConfiguration
{
    private static Func<string?, ClaimsPrincipal?, CancellationToken, Task<CertificateSigningRequestTemplate>> _factory =
        static (_, _, _) => Task.FromResult(new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null));

    public static void Reset()
    {
        _factory = static (_, _, _) => Task.FromResult(new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null));
    }

    public static void SetFactory(Func<string?, ClaimsPrincipal?, CancellationToken, Task<CertificateSigningRequestTemplate>> factory)
    {
        _factory = factory;
    }

    public static Task<CertificateSigningRequestTemplate> GetTemplate(
        string? profileName,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
    {
        return _factory(profileName, user, cancellationToken);
    }
}

internal class TestCsrAttributesLoader : ICsrTemplateLoader
{
    public async Task<CertificateSigningRequestTemplate> GetTemplate(
        string? profileName,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
    {
        return await TestCsrAttributesLoaderConfiguration.GetTemplate(profileName, user, cancellationToken);
    }
}
