﻿namespace OpenCertServer.Ca;

using System.Security.Cryptography.X509Certificates;

public interface ICertificateAuthority
{
    SignCertificateResponse SignCertificateRequest(CertificateRequest request, X509Certificate2? reenrollingFrom = null);

    SignCertificateResponse SignCertificateRequest(string request);

    X509Certificate2Collection GetRootCertificates();
}
