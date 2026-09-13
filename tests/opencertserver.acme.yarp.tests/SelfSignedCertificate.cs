namespace OpenCertServer.Acme.Yarp.Tests;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Produces self-signed certificates with an accessible private key, sufficient for the route-scoped
/// SNI and renewal tests that substitute for a live ACME-issued leaf.
/// </summary>
public static class SelfSignedCertificate
{
    public static X509Certificate2 MakeWithSubject(string subjectName, DateTimeOffset from, DateTimeOffset to)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={subjectName}", ecdsa, HashAlgorithmName.SHA256);
        return req.CreateSelfSigned(from, to);
    }
}
