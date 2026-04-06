namespace OpenCertServer.Acme.Abstractions.HttpModel;

using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Represents an error object for ACME operations.
/// See RFC 8555, section 6.7.
/// </summary>
public sealed class AcmeError
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AcmeError"/> class from a model error.
    /// </summary>
    /// <param name="model">The model error object.</param>
    public AcmeError(Model.AcmeError model)
    {
        if (model is null)
        {
            throw new ArgumentNullException(nameof(model));
        }

        Type = model.Type;
        Detail = model.Detail;

        if (model.Identifier != null)
        {
            Identifier = new Identifier(model.Identifier);
        }

        Subproblems = model.SubErrors?
            .Select(x => new AcmeError(x))
            .ToList();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AcmeError"/> class with a type and detail message.
    /// </summary>
    /// <param name="type">The error type URN.</param>
    /// <param name="detail">The error detail message.</param>
    public AcmeError(string type, string detail)
    {
        Type = type;
        Detail = detail;
    }

    /// <summary>
    /// Gets or sets the HTTP status code associated with the problem document.
    /// </summary>
    public int? Status { get; set; }

    /// <summary>
    /// Gets or sets the error type URN.
    /// </summary>
    public string Type { get; set; }

    /// <summary>
    /// Gets or sets the error detail message.
    /// </summary>
    public string Detail { get; set; }

    /// <summary>
    /// Gets or sets the list of subproblem errors, if any.
    /// </summary>
    public List<AcmeError>? Subproblems { get; set; }

    /// <summary>
    /// Gets or sets the identifier associated with the error, if any.
    /// </summary>
    public Identifier? Identifier { get; set; }
}
