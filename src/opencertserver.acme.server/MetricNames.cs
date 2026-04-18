namespace OpenCertServer.Acme.Server;

/// <summary>
/// Centralised metric name constants for all ACME OpenTelemetry instruments.
/// All metric instrument creation MUST reference these constants.
/// </summary>
internal static class MetricNames
{
    internal const string MeterName = "opencertserver.acme";

    // /directory
    internal const string DirectoryRequests  = "opencertserver.acme.directory.requests";
    internal const string DirectorySuccesses = "opencertserver.acme.directory.successes";
    internal const string DirectoryFailures  = "opencertserver.acme.directory.failures";
    internal const string DirectoryDuration  = "opencertserver.acme.directory.duration";

    // /new-nonce
    internal const string NewNonceRequests  = "opencertserver.acme.newnonce.requests";
    internal const string NewNonceSuccesses = "opencertserver.acme.newnonce.successes";
    internal const string NewNonceFailures  = "opencertserver.acme.newnonce.failures";
    internal const string NewNonceDuration  = "opencertserver.acme.newnonce.duration";

    // /new-account
    internal const string NewAccountRequests  = "opencertserver.acme.newaccount.requests";
    internal const string NewAccountSuccesses = "opencertserver.acme.newaccount.successes";
    internal const string NewAccountFailures  = "opencertserver.acme.newaccount.failures";
    internal const string NewAccountDuration  = "opencertserver.acme.newaccount.duration";

    // /new-order
    internal const string NewOrderRequests  = "opencertserver.acme.neworder.requests";
    internal const string NewOrderSuccesses = "opencertserver.acme.neworder.successes";
    internal const string NewOrderFailures  = "opencertserver.acme.neworder.failures";
    internal const string NewOrderDuration  = "opencertserver.acme.neworder.duration";

    // /order/{id}/finalize
    internal const string OrderFinalizeRequests  = "opencertserver.acme.orderfinalize.requests";
    internal const string OrderFinalizeSuccesses = "opencertserver.acme.orderfinalize.successes";
    internal const string OrderFinalizeFailures  = "opencertserver.acme.orderfinalize.failures";
    internal const string OrderFinalizeDuration  = "opencertserver.acme.orderfinalize.duration";

    // /order/{id}/certificate
    internal const string CertificateRequests  = "opencertserver.acme.certificate.requests";
    internal const string CertificateSuccesses = "opencertserver.acme.certificate.successes";
    internal const string CertificateFailures  = "opencertserver.acme.certificate.failures";
    internal const string CertificateDuration  = "opencertserver.acme.certificate.duration";

    // Challenge validation (ValidationWorker)
    internal const string ChallengeValidationRequests  = "opencertserver.acme.challengevalidation.requests";
    internal const string ChallengeValidationSuccesses = "opencertserver.acme.challengevalidation.successes";
    internal const string ChallengeValidationFailures  = "opencertserver.acme.challengevalidation.failures";
    internal const string ChallengeValidationDuration  = "opencertserver.acme.challengevalidation.duration";
    internal const string ChallengeValidationActive    = "opencertserver.acme.challengevalidation.active";

    // /key-change
    internal const string KeyChangeRequests  = "opencertserver.acme.keychange.requests";
    internal const string KeyChangeSuccesses = "opencertserver.acme.keychange.successes";
    internal const string KeyChangeFailures  = "opencertserver.acme.keychange.failures";
    internal const string KeyChangeDuration  = "opencertserver.acme.keychange.duration";

    // /revoke-cert
    internal const string RevokeRequests  = "opencertserver.acme.revoke.requests";
    internal const string RevokeSuccesses = "opencertserver.acme.revoke.successes";
    internal const string RevokeFailures  = "opencertserver.acme.revoke.failures";
    internal const string RevokeDuration  = "opencertserver.acme.revoke.duration";
}

