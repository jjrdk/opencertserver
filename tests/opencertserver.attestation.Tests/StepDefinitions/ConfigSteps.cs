using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Reqnroll;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

[Binding]
public class ConfigSteps
{
    private string _cloudContext = "Azure";
    private GlobalAttestationService? _service;

    [Given(@"a config file specifying ""(.*)"" as the context")]
    public void GivenAConfigFileSpecifyingAsTheContext(string context)
    {
        _cloudContext = context;
    }

    [When(@"the AttestationService initializes")]
    public void WhenTheAttestationServiceInitializes()
    {
        var options = Options.Create(new AttestationOptions
        {
            CloudContext = _cloudContext,
            IntelSgx = new IntelSgxOptions { PccsUrl = "https://pccs.confidentialcomputing.azure.com" },
            AmdSevSnp = new AmdSevSnpOptions { VpsUrl = "https://amd-vps.confidentialcomputing.azure.com" },
            AppleSE = new AppleSeOptions { VerifyUrl = "https://appattest.apple.com" }
        });

        var services = new ServiceCollection();
        services.AddSingleton(options);
        services.AddTransient<GlobalAttestationService>();
        services.AddSingleton<IAttestationProvider>(new Mocks.MockProvider { VendorName = "Intel" });

        var sp = services.BuildServiceProvider();
        _service = sp.GetRequiredService<GlobalAttestationService>();
    }

    [Then(@"it should select (.*) as the Intel SGX endpoint")]
    public void ThenItShouldSelectAsTheIntelSgxEndpoint(string expectedUrl)
    {
        var url = _service!.GetEndpointForVendor("Intel");
        if (url != expectedUrl)
        {
            throw new Exception($"Expected {expectedUrl} but found {url}");
        }
    }
}
