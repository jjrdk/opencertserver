using System.Runtime.CompilerServices;

namespace OpenCertServer.Acme.Abstractions.Exceptions;

public sealed class NotInitializedException : InvalidOperationException
{
    public NotInitializedException([CallerMemberName]string caller = null!)
        :base($"{caller} has been accessed before being initialized.")
    {

    }
}