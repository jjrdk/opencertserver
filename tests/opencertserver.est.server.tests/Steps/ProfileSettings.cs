namespace OpenCertServer.Est.Tests;

using System.Security.Cryptography.X509Certificates;

/// <summary>What a scenario fixes on a CA profile: the content the CA writes regardless of the CSR.</summary>
public sealed record ProfileSettings(
    IReadOnlyList<string>? AllowedCsrExtensions = null,
    IReadOnlyList<string>? CertificatePolicies = null,
    X509KeyUsageFlags? KeyUsage = null,
    IReadOnlyList<string>? ExtendedKeyUsages = null);
