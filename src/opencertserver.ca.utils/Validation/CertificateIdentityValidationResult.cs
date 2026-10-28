namespace OpenCertServer.Ca.Utils.Validation;

/// <summary>
/// The outcome of an RFC 9525 service-identity validation. On success
/// <see cref="MatchedIdentifier"/> is the reference identifier the client
/// <em>MUST</em> use as the validated identity (RFC 9525 §4.3.4).
/// </summary>
public sealed record CertificateIdentityValidationResult
{
    /// <summary>Indicates whether a presented identifier matched an acceptable reference identifier.</summary>
    public required bool IsMatch { get; init; }

    /// <summary>The reference identifier that matched, or <see langword="null"/> on failure.</summary>
    public ServiceIdentity? MatchedIdentifier { get; init; }

    /// <summary>The failure reason when <see cref="IsMatch"/> is <see langword="false"/>; otherwise <see langword="null"/>.</summary>
    public CertificateIdentityValidationFailure? Failure { get; init; }

    /// <summary>Creates a successful result for the matched reference identifier.</summary>
    public static CertificateIdentityValidationResult Matched(ServiceIdentity identifier) =>
        new() { IsMatch = true, MatchedIdentifier = identifier };

    /// <summary>Creates a failed result with the given reason.</summary>
    public static CertificateIdentityValidationResult Unmatched(CertificateIdentityValidationFailure failure) =>
        new() { IsMatch = false, Failure = failure };
}
