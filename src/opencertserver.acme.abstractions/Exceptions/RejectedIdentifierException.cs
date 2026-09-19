namespace OpenCertServer.Acme.Abstractions.Exceptions;

using System;
using System.Collections.Generic;

/// <summary>
/// Exception thrown when the server refuses to issue a certificate for one or more
/// requested identifiers. Maps to the ACME "rejectedIdentifier" error type
/// (RFC 8555 §6.7) and, when emitted as a problem document, carries a subproblem per
/// rejected identifier (RFC 8555 §6.7.1).
/// </summary>
public sealed class RejectedIdentifierException : AcmeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RejectedIdentifierException"/> class.
    /// </summary>
    /// <param name="rejectedIdentifiers">The identifiers that were rejected, each with a reason.</param>
    /// <param name="detail">
    /// The top-level human-readable detail, or <c>null</c> to use a default message.
    /// </param>
    public RejectedIdentifierException(IEnumerable<RejectedIdentifier> rejectedIdentifiers, string? detail = null)
        : base(detail ?? "The server will not issue certificates for the requested identifier(s).")
    {
        ArgumentNullException.ThrowIfNull(rejectedIdentifiers);
        RejectedIdentifiers = [.. rejectedIdentifiers];
    }

    /// <summary>
    /// Gets the identifiers that were rejected, along with the reason each was rejected.
    /// </summary>
    public IReadOnlyList<RejectedIdentifier> RejectedIdentifiers { get; }

    /// <inheritdoc/>
    public override string ErrorType
    {
        get { return "rejectedIdentifier"; }
    }
}
