using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Tests;

internal class ValidateAll : IValidateX509Chains
{
    public bool Validate(X509Chain chain)
    {
        return true;
    }
}
