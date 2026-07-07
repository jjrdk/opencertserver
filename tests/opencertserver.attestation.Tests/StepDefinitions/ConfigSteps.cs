using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Reqnroll;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

[Binding]
public class ConfigSteps
{
    private IConfiguration? _config;
    private GlobalAttestationService? _service;

    [Given(@"a config file specifying ""(.*)"" as the context")]
    public void GivenAConfigFileSpecifyingAsTheContext(string context)
    {
        var dict = new Dictionary<string, string?> {
            {"Global:CloudContext", context},
            {"Providers:Intel:PccsUrl", "https://pccs.confidentialcomputing.azure.com"}
        };
        _config = new ConfigurationBuilder()
            .AddInMemoryCollection(dict)
            .Build();
    }

    [When(@"the AttestationService initializes")]
    public void WhenTheAttestationServiceInitializes()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(_config!);
        services.AddTransient<GlobalAttestationService>();

        // Add a mock provider to avoid NotSupportedException in GetProvider()
        services.AddSingleton<IAttestationProvider>(new OpenCertServer.Attestation.Tests.Mocks.MockProvider { VendorName = "Intel" });

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
