namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Collections.Generic;
using Acme.Abstractions.Services;
using CertesSlim.Acme.Resource;

internal sealed class TestAllowedIdentifiersPolicy : IAllowedIdentifiersPolicy
{
    private static readonly HashSet<string> RejectedIdentifiers = new(StringComparer.OrdinalIgnoreCase)
    {
        "rejected-a.local",
        "rejected-b.local"
    };

    public string? GetRejectionReason(Identifier identifier)
        => RejectedIdentifiers.Contains(identifier.Value)
            ? $"The identifier '{identifier.Value}' is not permitted by the certificate authority policy."
            : null;
}