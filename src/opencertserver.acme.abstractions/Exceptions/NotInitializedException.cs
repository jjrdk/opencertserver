using System.Runtime.CompilerServices;

namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when an object or member is accessed before being properly initialized.
/// </summary>
public sealed class NotInitializedException : InvalidOperationException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NotInitializedException"/> class with a message indicating the uninitialized member.
    /// </summary>
    /// <param name="caller">The name of the member that was accessed before initialization.</param>
    public NotInitializedException([CallerMemberName]string caller = null!)
        :base($"{caller} has been accessed before being initialized.")
    {

    }
}
