namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using Reqnroll;

[Binding]
public sealed class CertificateServerStorageSteps(ScenarioContext scenarioContext)
{
    [Given(@"the certificate server storage is ""(.*)""")]
    public void GivenTheCertificateServerStorageIs(string storage) =>
        CertificateServerStorage.Select(scenarioContext, storage);
}
