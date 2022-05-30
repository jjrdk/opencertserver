﻿namespace OpenCertServer.Acme.Abstractions.IssuanceServices
{
    using System.Threading;
    using System.Threading.Tasks;
    using Model;

    public interface ICertificateIssuer
    {
        Task<(byte[]? certificate, AcmeError? error)> IssueCertificate(string csr, CancellationToken cancellationToken);
    }
}
