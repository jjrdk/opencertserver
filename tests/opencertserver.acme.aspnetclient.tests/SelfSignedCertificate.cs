namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class SelfSignedCertificate
{
    public static X509Certificate2 Make(DateTime from, DateTime to)
    {
        using var ecdsa = ECDsa.Create();
        var req = new CertificateRequest("cn=foobar", ecdsa, HashAlgorithmName.SHA256);
        return req.CreateSelfSigned(from, to);
    }

    /// <summary>
    /// Creates a self-signed certificate with the specified CN subject and validity window.
    /// The returned certificate has an accessible private key.
    /// </summary>
    public static X509Certificate2 MakeWithSubject(string subjectName, DateTimeOffset from, DateTimeOffset to)
    {
        using var ecdsa = ECDsa.Create();
        var req = new CertificateRequest($"cn={subjectName}", ecdsa, HashAlgorithmName.SHA256);
        return req.CreateSelfSigned(from, to);
    }
}

