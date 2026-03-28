using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Abstractions.Model;

using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Represents an ACME error object, including type, detail, optional identifier, and subproblems.
/// </summary>
public sealed class AcmeError
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AcmeError"/> class for deserialization.
    /// </summary>
    private AcmeError()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AcmeError"/> class with the specified type, detail, identifier, and subproblems.
    /// </summary>
    /// <param name="type">The error type URN or short name (will be normalized to a URN if needed).</param>
    /// <param name="detail">The error detail message.</param>
    /// <param name="identifier">The identifier associated with the error, if any.</param>
    /// <param name="subErrors">A collection of subproblem errors, if any.</param>
    public AcmeError(
        string type,
        string detail,
        Identifier? identifier = null,
        IEnumerable<AcmeError>? subErrors = null)
    {
        Type = type;

        if (!type.Contains(":"))
        {
            Type = "urn:ietf:params:acme:error:" + type;
        }

        Detail = detail;
        Identifier = identifier;
        SubErrors = subErrors?.ToList();
    }

    /// <summary>
    /// Gets the error type URN (e.g., urn:ietf:params:acme:error:malformed).
    /// </summary>
    public string Type
    {
        get { return field ?? throw new NotInitializedException(); }
        private set;
    }

    /// <summary>
    /// Gets or sets the error detail message.
    /// </summary>
    public string Detail
    {
        get { return field ?? throw new NotInitializedException(); }
        set;
    }

    /// <summary>
    /// Gets the identifier associated with the error, if any.
    /// </summary>
    public Identifier? Identifier { get; }

    /// <summary>
    /// Gets the list of subproblem errors, if any.
    /// </summary>
    public List<AcmeError>? SubErrors { get; }
}
