namespace OpenCertServer.Tpm.Tests;

using System;
using System.Runtime.CompilerServices;
using Xunit;

/// <summary>
/// A standard <see cref="FactAttribute"/> for TPM tests.
/// Simulator connectivity is now handled by <see cref="TpmContainerHooks"/>,
/// which starts a fresh Docker container before each scenario.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class TpmFactAttribute : FactAttribute
{
    // xUnit v3 requires source-information constructor.
    public TpmFactAttribute(
        [CallerFilePath] string? sourceFile = null,
        [CallerLineNumber] int sourceLine = 0)
    {
    }
}

