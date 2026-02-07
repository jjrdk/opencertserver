using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Ca.Utils.X509;
using Reqnroll;
using Xunit;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

public partial class CertificateServerFeatures
{
    [When("I check OCSP for an unknown certificate")]
    public async Task WhenICheckOcspForAnUnknownCertificate()
    {
        using var client = _server.CreateClient();
        var tbsRequest = new TbsRequest(requestList:
        [
            new Request(new CertId(new AlgorithmIdentifier(Oids.RsaOid),
                "abc"u8.ToArray(),
                "abc"u8.ToArray(),
                "123"u8.ToArray()))
        ]);
        var ocspRequest = new OcspRequest(tbsRequest);
        var ocspResponse = await GetOcspResponse(ocspRequest);

        Assert.NotNull(ocspResponse);

        _scenarioContext["ocspResponse"] = ocspResponse;
    }

    [Then("the certificate should be valid in OCSP")]
    public async Task ThenTheCertificateShouldBeValidInOcsp()
    {
        using var client = _server.CreateClient();
        var tbsRequest = new TbsRequest(requestList:
        [
            new Request(CertId.Create(_certCollection[0], HashAlgorithmName.SHA256))
        ]);
        var signature = tbsRequest.Sign(_key);
        var ocspRequest = new OcspRequest(tbsRequest, signature);
        var ocspResponse = await GetOcspResponse(ocspRequest);
        Assert.Equal(OcspResponseStatus.Successful, ocspResponse.ResponseStatus);
        var basicResponse = ocspResponse.ResponseBytes!.GetBasicResponse();
        Assert.Single(basicResponse.TbsResponseData.Responses);
        var singleResponse = basicResponse.TbsResponseData.Responses.First();
        Assert.Equal(CertificateStatus.Good, singleResponse.CertStatus);
    }

    [Then("the certificate should be revoked in OCSP")]
    public async Task ThenTheCertificateShouldBeRevokedInOcsp()
    {
        var serialNumberString = _certCollection[0].SerialNumberBytes;
        var tbsRequest = new TbsRequest(requestList:
        [
            new Request(CertId.Create(_certCollection[0], HashAlgorithmName.SHA256))
        ]);
        var signature = tbsRequest.Sign(_key);
        var ocspRequest = new OcspRequest(tbsRequest, signature);
        var ocspResponse = await GetOcspResponse(ocspRequest);
        Assert.Equal(OcspResponseStatus.Successful, ocspResponse.ResponseStatus);
        var basicResponse = ocspResponse.ResponseBytes!.GetBasicResponse();
        Assert.Single(basicResponse.TbsResponseData.Responses);
        var singleResponse = basicResponse.TbsResponseData.Responses.First();
        Assert.Equal(CertificateStatus.Revoked, singleResponse.CertStatus);
    }

    private async Task<OcspResponse> GetOcspResponse(OcspRequest ocspRequest)
    {
        using var client = _server.CreateClient();
        var request = new HttpRequestMessage(
            HttpMethod.Post,
            "ca/ocsp")
        {
            Content = new ByteArrayContent(ocspRequest.GetBytes())
        };
        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var ocspResponseBytes = response.Content.ReadAsByteArrayAsync().Result;
        var ocspResponse = new OcspResponse(new AsnReader(ocspResponseBytes, AsnEncodingRules.DER));
        return ocspResponse;
    }

    [Then("the response should indicate the certificate is unknown")]
    public void ThenTheResponseShouldIndicateTheCertificateIsUnknown()
    {
        var ocspResponse = (OcspResponse)_scenarioContext["ocspResponse"]!;
        Assert.Equal(OcspResponseStatus.Successful, ocspResponse.ResponseStatus);
        var basicResponse = ocspResponse.ResponseBytes!.GetBasicResponse();
        Assert.Single(basicResponse.TbsResponseData.Responses);
        var singleResponse = basicResponse.TbsResponseData.Responses.First();
        Assert.Equal(CertificateStatus.Unknown, singleResponse.CertStatus);
    }
}
