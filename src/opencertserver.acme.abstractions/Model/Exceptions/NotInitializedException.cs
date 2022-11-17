namespace OpenCertServer.Acme.Abstractions.Model.Exceptions;

using System;
using System.Runtime.CompilerServices;

public sealed class NotInitializedException : InvalidOperationException
{
    public NotInitializedException([CallerMemberName]string caller = null!)
        :base($"{caller} has been accessed before being initialized.")
    {

    }
}