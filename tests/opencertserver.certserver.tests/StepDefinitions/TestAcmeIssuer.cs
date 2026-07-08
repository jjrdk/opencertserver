namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using Acme.Abstractions.IssuanceServices;
using Acme.Abstractions.Model;
using CertServer;

internal sealed class TestAcmeIssuer : IIssueCertificates
{
    private readonly DefaultIssuer _innerIssuer;

    public TestAcmeIssuer(DefaultIssuer innerIssuer)
    {
        _innerIssuer = innerIssuer;
    }

    public bool FailNextIssuance { get; set; }

    public string FailureType { get; set; } = "serverInternal";

    public string FailureDetail { get; set; } = "Simulated issuance failure.";

    public async Task<(byte[]? certificate, AcmeError? error)> IssueCertificate(
        string? profile,
        string csr,
        IEnumerable<Identifier> identifiers,
        DateTimeOffset? notBefore,
        DateTimeOffset? notAfter,
        CancellationToken cancellationToken)
    {
        if (FailNextIssuance)
        {
            FailNextIssuance = false;
            return (null, new AcmeError(FailureType, FailureDetail));
        }

        return await _innerIssuer
            .IssueCertificate(profile, csr, identifiers, notBefore, notAfter, cancellationToken)
            .ConfigureAwait(false);
    }
}

