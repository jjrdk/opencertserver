using System.Collections.Generic;

namespace CertesSlim.Pkcs;

/// <summary>
/// Supports building Certificate Signing Request (CSR).
/// </summary>
public interface ICertificationRequestBuilder
{
    /// <summary>
    /// Generates the CSR.
    /// </summary>
    /// <returns>The CSR data.</returns>
    byte[] Generate();
}