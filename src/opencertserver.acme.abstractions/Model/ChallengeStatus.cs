namespace OpenCertServer.Acme.Abstractions.Model;

public enum ChallengeStatus
{
    Pending,
    Processing,
    Valid,
    Invalid
}