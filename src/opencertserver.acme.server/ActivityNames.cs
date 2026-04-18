namespace OpenCertServer.Acme.Server;

/// <summary>
/// Centralised activity (span) name constants for all ACME OpenTelemetry traces.
/// All spans MUST reference these constants; never use inline string literals for activity names.
/// </summary>
internal static class ActivityNames
{
    internal const string Directory          = "opencertserver.acme.directory";
    internal const string NewNonce           = "opencertserver.acme.newnonce";
    internal const string NewAccount         = "opencertserver.acme.newaccount";
    internal const string NewOrder           = "opencertserver.acme.neworder";
    internal const string OrderFinalize      = "opencertserver.acme.orderfinalize";
    internal const string Certificate        = "opencertserver.acme.certificate";
    internal const string ChallengeValidation = "opencertserver.acme.challengevalidation";
    internal const string KeyChange          = "opencertserver.acme.keychange";
    internal const string Revoke             = "opencertserver.acme.revoke";
}

