using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Est.Tests.Steps;

/// <summary>What a scenario fixes on a CA profile: the content the CA writes regardless of the CSR.</summary>
public sealed record ProfileSettings(
    IReadOnlyList<string>? AllowedCsrExtensions = null,
    IReadOnlyList<string>? CertificatePolicies = null,
    X509KeyUsageFlags? KeyUsage = null,
    IReadOnlyList<string>? ExtendedKeyUsages = null);
