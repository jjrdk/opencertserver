using OpenCertServer.Ca.Protocol;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using Reqnroll;
using Xunit;

/// <summary>
/// Contract steps for the shared RA/CA protocol package. The constant values are pinned here so a
/// change on one side of the wire (the RA or the CA) that desynchronizes the contract fails this
/// scenario; the end-to-end scenarios in the same feature prove the two sides still agree at runtime.
/// </summary>
[Binding]
public sealed class RaProtocolSteps
{
    [When(@"the RA and CA protocol constants are compared")]
    public void WhenTheRaCaProtocolConstantsAreCompared()
    {
        // The wire contract is pinned to exact literals so a one-sided change is caught here.
        Assert.Equal("ca/csr", RaProtocol.CsrPath);
        Assert.Equal("ca/revoke", RaProtocol.RevokePath);
        Assert.Equal("X-Delegated-Subject", RaProtocol.DelegatedSubjectHeader);
        Assert.Equal("ra", RaProtocol.RaIdClaim);
        Assert.Equal("delegated-subject", RaProtocol.DelegatedSubjectClaim);
        Assert.False(string.IsNullOrWhiteSpace(RaProtocol.RaProtocolVersion));
    }

    [Then(@"the shared paths, claims and headers are defined")]
    public void ThenTheSharedPathsClaimsAndHeadersAreDefined()
    {
        Assert.NotEqual(RaProtocol.CsrPath, RaProtocol.RevokePath);

        // RaClaimTypes must alias the protocol constants so both sides read the same source.
        Assert.Equal(RaProtocol.DelegatedSubjectHeader, RaClaimTypes.DelegatedSubjectHeader);
        Assert.Equal(RaProtocol.RaIdClaim, RaClaimTypes.RaId);
        Assert.Equal(RaProtocol.DelegatedSubjectClaim, RaClaimTypes.DelegatedSubject);

        // The revocation proof-of-possession message is canonical and shared by both sides.
        Assert.Equal(
            "482E7A5CEC02F46BCessationOfOperation",
            RaProtocol.BuildRevocationMessage("482E7A5CEC02F46B", "CessationOfOperation"));
    }

    [Then(@"the current protocol version is accepted and unsupported versions are rejected")]
    public void ThenTheCurrentProtocolVersionIsAcceptedAndUnsupportedVersionsAreRejected()
    {
        Assert.True(RaProtocol.IsSupportedVersion(null));
        Assert.True(RaProtocol.IsSupportedVersion(RaProtocol.RaProtocolVersion));
        Assert.False(RaProtocol.IsSupportedVersion("999"));
    }
}
