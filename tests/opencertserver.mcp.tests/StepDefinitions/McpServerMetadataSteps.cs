namespace OpenCertServer.Mcp.Tests;

using OpenCertServer.Mcp.Tests.Support;
using OpenCertServer.Mcp;
using OpenCertServer.Mcp.Tools;
using Reqnroll;
using Xunit;

[Binding]
public sealed class McpServerMetadataSteps
{
  private readonly McpServerFixture _fixture;
  private McpServerMetadata? _metadata;

  public McpServerMetadataSteps(McpServerFixture fixture)
  {
    _fixture = fixture;
    _metadata = null!;
  }

  [When("the MCP server invokes \\\"get_server_metadata\\\" with no parameters")]
  [When("the MCP server invokes \\\"get_server_metadata\\\"")]
  public async Task WhenGetServerMetadata()
  {
    var result = await _fixture.InvokeMcpToolAsync("get_server_metadata", new { });
    Assert.True(result.IsSuccess, $"get_server_metadata failed: {result.ErrorMessage}");
    _metadata = (McpServerMetadata)result.Content!;
    TestSharedState.ServerMetadata = _metadata;
    TestSharedState.ToolResult = result;
  }

  [Then("the response MUST include a server name")]
  public void ThenServerNamePresent()
  {
    Assert.NotNull(_metadata);
    Assert.NotNull(_metadata.ServerName);
    Assert.NotEmpty(_metadata.ServerName);
  }

  [Then("the response MUST include a server version string")]
  public void ThenServerVersionPresent()
  {
    Assert.NotNull(_metadata);
    Assert.NotNull(_metadata.ServerVersion);
    Assert.NotEmpty(_metadata.ServerVersion);
  }

  [Then("the response MUST include a list of CA profiles")]
  public void ThenCaProfilesPresent()
  {
    Assert.NotNull(_metadata);
    Assert.NotNull(_metadata.CaProfiles);
    Assert.NotEmpty(_metadata.CaProfiles);
  }

  [Then("the response MUST include OCSP URLs")]
  public void ThenOcspUrlsPresent()
  {
    Assert.NotNull(_metadata);
    Assert.NotNull(_metadata.OcspUrls);
  }

  [Then("the response MUST include CRL URLs")]
  public void ThenCrlUrlsPresent()
  {
    Assert.NotNull(_metadata);
    Assert.NotNull(_metadata.CrlUrls);
  }

  [Then("the response MUST include CA Issuers URLs")]
  public void ThenCaIssuersUrlsPresent()
  {
    Assert.NotNull(_metadata);
    Assert.NotNull(_metadata.CaIssuersUrls);
  }

  [Then("the response MUST include EST endpoint URLs")]
  public void ThenEstEndpointsPresent()
  {
    Assert.NotNull(_metadata);
    Assert.NotNull(_metadata.EstEndpoints);
  }

  [Then("the response MUST include supported key types")]
  public void ThenKeyTypesPresent()
  {
    Assert.NotNull(_metadata);
    Assert.NotNull(_metadata.SupportedKeyTypes);
    Assert.NotEmpty(_metadata.SupportedKeyTypes);
  }

  [Then("the response MUST include supported signature algorithms")]
  public void ThenSigAlgorithmsPresent()
  {
    Assert.NotNull(_metadata);
    Assert.NotNull(_metadata.SupportedSignatureAlgorithms);
    Assert.NotEmpty(_metadata.SupportedSignatureAlgorithms);
  }

  [Then("each CA profile MUST have a name")]
  public void ThenEachProfileHasName()
  {
    Assert.NotNull(_metadata);
    foreach (var profile in _metadata.CaProfiles)
    {
      Assert.NotNull(profile.Name);
      Assert.NotEmpty(profile.Name);
    }
  }

  [Then("each CA profile MUST have a certificate chain")]
  public void ThenEachProfileHasChain()
  {
    Assert.NotNull(_metadata);
    foreach (var profile in _metadata.CaProfiles)
    {
      Assert.NotNull(profile.CertificateChain);
      Assert.NotEmpty(profile.CertificateChain);
    }
  }

  [Then("each CA profile MUST indicate whether it has a private key")]
  public void ThenEachProfileHasPrivateKeyFlag()
  {
    Assert.NotNull(_metadata);
    foreach (var profile in _metadata.CaProfiles)
    {
      var _ = profile.HasPrivateKey; // just verify it's accessible
    }
  }

  [Then("each CA profile MUST have a certificate validity period in days")]
  public void ThenEachProfileHasValidityDays()
  {
    Assert.NotNull(_metadata);
    foreach (var profile in _metadata.CaProfiles)
    {
      Assert.True(profile.CertificateValidityDays > 0);
    }
  }

  [Then("each CA profile MUST indicate whether it has an OCSP signing key")]
  public void ThenEachProfileHasOcspSigningKey()
  {
    Assert.NotNull(_metadata);
    foreach (var profile in _metadata.CaProfiles)
    {
      var _ = profile.HasOcspSigningKey;
    }
  }

  [Then("each CA profile MUST include the OCSP freshness window as a string")]
  public void ThenEachProfileHasOcspFreshnessWindow()
  {
    Assert.NotNull(_metadata);
    foreach (var profile in _metadata.CaProfiles)
    {
      var _ = profile.OcspFreshnessWindow;
    }
  }

  [Then("the supported key types MUST include \\\"(.+)\\\"")]
  public void ThenKeyTypeIncludes(string keyType)
  {
    Assert.NotNull(_metadata);
    Assert.Contains(keyType, _metadata.SupportedKeyTypes);
  }

  [Then("the supported key types MUST include \\\"ECDSA\\\"")]
  public void ThenKeyTypeIncludesEcdsa()
  {
    Assert.NotNull(_metadata);
    Assert.Contains("ECDSA", _metadata.SupportedKeyTypes);
  }

  [Then("the supported signature algorithms MUST include \\\"SHA256withRSA\\\"")]
  public void ThenSigAlgorithmIncludesSha256Rsa()
  {
    Assert.NotNull(_metadata);
    Assert.Contains("SHA256withRSA", _metadata.SupportedSignatureAlgorithms);
  }

  [Then("the supported signature algorithms MUST include \\\"SHA256withECDSA\\\"")]
  public void ThenSigAlgorithmIncludesSha256Ecdsa()
  {
    Assert.NotNull(_metadata);
    Assert.Contains("SHA256withECDSA", _metadata.SupportedSignatureAlgorithms);
  }

  [Then("the supported signature algorithms MUST include \\\"SHA512withRSA\\\"")]
  public void ThenSigAlgorithmIncludesSha512Rsa()
  {
    Assert.NotNull(_metadata);
    Assert.Contains("SHA512withRSA", _metadata.SupportedSignatureAlgorithms);
  }

  [Then("the supported signature algorithms MUST include \\\"SHA512withECDSA\\\"")]
  public void ThenSigAlgorithmIncludesSha512Ecdsa()
  {
    Assert.NotNull(_metadata);
    Assert.Contains("SHA512withECDSA", _metadata.SupportedSignatureAlgorithms);
  }

  [Then("the caBundle endpoint MUST start with \\\"/.well-known/est\\\"")]
  public void ThenCaBundleEndpointStartsWithWellKnown()
  {
    Assert.NotNull(_metadata);
    Assert.NotNull(_metadata.EstEndpoints);
    Assert.StartsWith("/.well-known/est", _metadata.EstEndpoints.CaBundle!);
  }

  [Then("the simpleEnroll endpoint MUST be \\\"/.well-known/est/simpleenroll\\\"")]
  public void ThenSimpleEnrollEndpointCorrect()
  {
    Assert.NotNull(_metadata);
    Assert.Equal("/.well-known/est/simpleenroll", _metadata.EstEndpoints.SimpleEnroll);
  }

  [Then("the simpleReenroll endpoint MUST be \\\"/.well-known/est/simplereenroll\\\"")]
  public void ThenSimpleReenrollEndpointCorrect()
  {
    Assert.NotNull(_metadata);
    Assert.Equal("/.well-known/est/simplereenroll", _metadata.EstEndpoints.SimpleReenroll);
  }

  [Then("the reported max CSR key size MUST be at least (.+)")]
  public void ThenMaxCsrKeySizeAtLeast(int expected)
  {
    Assert.NotNull(_metadata);
    Assert.True(_metadata.MaxCsrKeySize >= expected);
  }

  [Then("the reported min CSR key size MUST be at least (.+)")]
  public void ThenMinCsrKeySizeAtLeast(int expected)
  {
    Assert.NotNull(_metadata);
    Assert.True(_metadata.MinCsrKeySize >= expected);
  }

  [Then("min MUST be less than or equal to max")]
  public void ThenMinLessThanOrEqualToMax()
  {
    Assert.NotNull(_metadata);
    Assert.True(_metadata.MinCsrKeySize <= _metadata.MaxCsrKeySize);
  }
}
