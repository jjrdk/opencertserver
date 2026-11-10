namespace OpenCertServer.Contrib.Intune;

using System.Text.Json.Serialization;

// The wire shapes of Microsoft's SCEP validation service (Intune-Resource-Access,
// CsrValidation) and of the token endpoint - as records, serialized through a
// source-generated context, so the package stays trimmable and AOT-compatible like
// the rest of OpenCertServer.

internal sealed record TokenReply(
    [property: JsonPropertyName("access_token")] string? AccessToken,
    [property: JsonPropertyName("expires_in")] int ExpiresIn);

internal sealed record IntuneReply(
    [property: JsonPropertyName("code")] string? Code,
    [property: JsonPropertyName("errorDescription")] string? ErrorDescription);

internal sealed record ValidateBody(
    [property: JsonPropertyName("transactionId")] string TransactionId,
    [property: JsonPropertyName("certificateRequest")] string CertificateRequest,
    [property: JsonPropertyName("callerInfo")] string CallerInfo);

internal sealed record ValidateEnvelope([property: JsonPropertyName("request")] ValidateBody Request);

internal sealed record SuccessBody(
    [property: JsonPropertyName("transactionId")] string TransactionId,
    [property: JsonPropertyName("certificateRequest")] string CertificateRequest,
    [property: JsonPropertyName("certificateThumbprint")] string CertificateThumbprint,
    [property: JsonPropertyName("certificateSerialNumber")] string CertificateSerialNumber,
    [property: JsonPropertyName("certificateExpirationDateUtc")] string CertificateExpirationDateUtc,
    [property: JsonPropertyName("issuingCertificateAuthority")] string IssuingCertificateAuthority,
    [property: JsonPropertyName("callerInfo")] string CallerInfo,
    [property: JsonPropertyName("caConfiguration")] string CaConfiguration,
    [property: JsonPropertyName("certificateAuthority")] string CertificateAuthority);

internal sealed record SuccessEnvelope([property: JsonPropertyName("notification")] SuccessBody Notification);

internal sealed record FailureBody(
    [property: JsonPropertyName("transactionId")] string TransactionId,
    [property: JsonPropertyName("certificateRequest")] string CertificateRequest,
    [property: JsonPropertyName("hResult")] long HResult,
    [property: JsonPropertyName("errorDescription")] string ErrorDescription,
    [property: JsonPropertyName("callerInfo")] string CallerInfo);

internal sealed record FailureEnvelope([property: JsonPropertyName("notification")] FailureBody Notification);

internal sealed record AssertionHeader(
    [property: JsonPropertyName("alg")] string Alg,
    [property: JsonPropertyName("typ")] string Typ,
    [property: JsonPropertyName("x5t")] string X5t,
    [property: JsonPropertyName("x5t#S256")] string X5tS256);

internal sealed record AssertionClaims(
    [property: JsonPropertyName("aud")] string Aud,
    [property: JsonPropertyName("iss")] string Iss,
    [property: JsonPropertyName("sub")] string Sub,
    [property: JsonPropertyName("jti")] string Jti,
    [property: JsonPropertyName("nbf")] long Nbf,
    [property: JsonPropertyName("exp")] long Exp);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(AssertionHeader))]
[JsonSerializable(typeof(AssertionClaims))]
[JsonSerializable(typeof(TokenReply))]
[JsonSerializable(typeof(IntuneReply))]
[JsonSerializable(typeof(ValidateEnvelope))]
[JsonSerializable(typeof(SuccessEnvelope))]
[JsonSerializable(typeof(FailureEnvelope))]
[JsonSerializable(typeof(SyncReport))]
internal sealed partial class IntuneJsonContext : JsonSerializerContext
{
}
