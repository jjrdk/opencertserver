﻿namespace OpenCertServer.Acme.Abstractions.IssuanceServices;

using System.Threading;
using System.Threading.Tasks;
using Model;

public interface ICsrValidator
{
    Task<(bool isValid, AcmeError? error)> ValidateCsr(Order order, string csr, CancellationToken cancellationToken);
}