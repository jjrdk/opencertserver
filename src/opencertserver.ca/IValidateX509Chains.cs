namespace OpenCertServer.Ca;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Defines the interface for validating X.509 certificate chains.
/// </summary>
public interface IValidateX509Chains
{
    /// <summary>
    /// Validates the given X.509 certificate chain.
    /// </summary>
    /// <param name="chain">The X.509 certificate chain to validate</param>
    /// <returns>True if the chain is valid, otherwise false</returns>
    bool Validate(X509Chain chain);
}
