namespace OpenCertServer.Contrib.Intune;

/// <summary>Centralised activity names for Intune operation traces.</summary>
internal static class ActivityNames
{
    internal const string ChallengeValidation = "opencertserver.intune.challenge.validation";
    internal const string SuccessNotification = "opencertserver.intune.notification.success";
    internal const string FailureNotification = "opencertserver.intune.notification.failure";
    internal const string RevocationSync = "opencertserver.intune.revocationsync";
}
