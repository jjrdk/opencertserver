namespace OpenCertServer.Contrib.Intune;

/// <summary>Centralised metric names for Intune operations.</summary>
internal static class MetricNames
{
    internal const string MeterName = "opencertserver.intune";

    internal const string ChallengeValidationRequests = "opencertserver.intune.challenge.validation.requests";
    internal const string ChallengeValidationSuccesses = "opencertserver.intune.challenge.validation.successes";
    internal const string ChallengeValidationFailures = "opencertserver.intune.challenge.validation.failures";
    internal const string ChallengeValidationDuration = "opencertserver.intune.challenge.validation.duration";

    internal const string SuccessNotificationRequests = "opencertserver.intune.notification.success.requests";
    internal const string SuccessNotificationSuccesses = "opencertserver.intune.notification.success.successes";
    internal const string SuccessNotificationFailures = "opencertserver.intune.notification.success.failures";
    internal const string SuccessNotificationDuration = "opencertserver.intune.notification.success.duration";

    internal const string FailureNotificationRequests = "opencertserver.intune.notification.failure.requests";
    internal const string FailureNotificationSuccesses = "opencertserver.intune.notification.failure.successes";
    internal const string FailureNotificationFailures = "opencertserver.intune.notification.failure.failures";
    internal const string FailureNotificationDuration = "opencertserver.intune.notification.failure.duration";

    internal const string RevocationSyncRequests = "opencertserver.intune.revocationsync.requests";
    internal const string RevocationSyncSuccesses = "opencertserver.intune.revocationsync.successes";
    internal const string RevocationSyncFailures = "opencertserver.intune.revocationsync.failures";
    internal const string RevocationSyncDuration = "opencertserver.intune.revocationsync.duration";
}
