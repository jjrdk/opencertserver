namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when an ACME client requests an existing account that does not exist.
/// </summary>
public sealed class AccountDoesNotExistException : AcmeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AccountDoesNotExistException"/> class.
    /// </summary>
    public AccountDoesNotExistException()
        : base("No account exists for the provided account key.")
    {
    }

    /// <inheritdoc />
    public override string ErrorType => "accountDoesNotExist";
}

