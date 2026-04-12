namespace OpenCertServer.Tpm.Tests;

using System;
using System.Runtime.CompilerServices;
using Xunit;

/// <summary>
/// A standard <see cref="FactAttribute"/> for TPM tests.
/// Simulator lifecycle is handled by <see cref="TpmContainerHooks"/>,
/// which starts one Docker container per feature and shares it across all scenarios in that feature.
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

