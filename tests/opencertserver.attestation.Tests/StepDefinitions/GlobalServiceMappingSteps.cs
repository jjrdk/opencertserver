using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenCertServer.Attestation.Tests.Mocks;
using Reqnroll;
using Xunit;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

[Binding]
public class GlobalServiceMappingSteps
{
    private AttestationOptions _options = new();
    private GlobalAttestationService? _service;
    private IAttestationProvider? _selectedProvider;
    private string? _selectedEndpoint;
    private Exception? _thrownException;

    private GlobalAttestationService BuildService(params (string vendorName, IAttestationProvider provider)[] providers)
    {
        var services = new ServiceCollection();
        foreach (var (_, p) in providers)
            services.AddSingleton<IAttestationProvider>(p);
        var sp = services.BuildServiceProvider();
        return new GlobalAttestationService(Options.Create(_options), sp);
    }

    [Given(@"the cloud context is ""(.*)"" with no vendor preference")]
    public void GivenCloudContextNoPreference(string context)
    {
        _options = new AttestationOptions
        {
            CloudContext = context,
            IntelSgx = new IntelSgxOptions { PccsUrl = "https://pccs.confidentialcomputing.azure.com" },
            AmdSevSnp = new AmdSevSnpOptions { VpsUrl = "https://amd-vps.confidentialcomputing.azure.com" },
            AppleSE = new AppleSeOptions { VerifyUrl = "https://appattest.apple.com" }
        };
    }

    [Given(@"the cloud context is ""(.*)"" with vendor preference ""(.*)""")]
    public void GivenCloudContextWithVendorPreference(string context, string vendor)
    {
        GivenCloudContextNoPreference(context);
        _options.VendorPreference = vendor;
    }

    [When(@"the AttestationService selects a provider")]
    public void WhenAttestationServiceSelectsProvider()
    {
        _service = BuildService(
            ("Intel", new MockProvider { VendorName = "Intel" }),
            ("AMD", new MockProvider { VendorName = "AMD" }),
            ("Apple", new MockProvider { VendorName = "Apple" }));
        try { _selectedProvider = _service.GetProvider(); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the AttestationService tries to select a provider")]
    public void WhenAttestationServiceTriesSelectProvider()
    {
        WhenAttestationServiceSelectsProvider();
    }

    [When(@"the endpoint for vendor ""(.*)"" is requested")]
    public void WhenEndpointRequested(string vendor)
    {
        _service = BuildService(
            ("Intel", new MockProvider { VendorName = "Intel" }),
            ("AMD", new MockProvider { VendorName = "AMD" }),
            ("Apple", new MockProvider { VendorName = "Apple" }));
        try { _selectedEndpoint = _service.GetEndpointForVendor(vendor); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [Then(@"the selected provider's VendorName should be ""(.*)""")]
    public void ThenProviderVendorName(string expectedVendor)
    {
        Assert.Null(_thrownException);
        Assert.NotNull(_selectedProvider);
        Assert.Equal(expectedVendor, _selectedProvider.VendorName);
    }

    [Then(@"the endpoint should be ""(.*)""")]
    public void ThenEndpointShouldBe(string expectedEndpoint)
    {
        Assert.Null(_thrownException);
        Assert.Equal(expectedEndpoint, _selectedEndpoint);
    }

    [Then(@"a NotSupportedException is thrown")]
    public void ThenNotSupportedExceptionThrown()
    {
        Assert.NotNull(_thrownException);
        Assert.IsType<NotSupportedException>(_thrownException);
    }
}
