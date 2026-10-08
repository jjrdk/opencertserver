using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Ca;

public sealed partial class OwnCertificateValidation : IValidateCertificateRequests
{
    private readonly IStoreCaProfiles _caProfiles;
    private readonly ILogger _logger;

    public OwnCertificateValidation(IStoreCaProfiles caProfiles, ILogger<OwnCertificateValidation> logger)
    {
        _caProfiles = caProfiles;
        _logger = logger;
    }

    public async Task<string?> Validate(
        CertificateRequest request,
        string? profile = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        CancellationToken cancellationToken = default)
    {
        var caProfile = await _caProfiles.GetProfile(profile, cancellationToken).ConfigureAwait(false);
        var result = reenrollingFrom == null
         || caProfile.CertificateChain
                .Aggregate(false, (b, cert) => b || reenrollingFrom.IssuerName.Name == cert.SubjectName.Name);
        if (result)
        {
            return null;
        }

        LogCouldNotValidateReEnrollmentFromReEnrollingFrom(reenrollingFrom!.IssuerName.Name);
        return "Re-enrollment certificate is not issued by this CA";
    }

    [LoggerMessage(LogLevel.Error, "Could not validate re-enrollment from {ReenrollingFrom}")]
    partial void LogCouldNotValidateReEnrollmentFromReEnrollingFrom(string reenrollingFrom);
}
