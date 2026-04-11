using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when an ACME resource is in a conflicting state or status.
/// </summary>
public sealed class ConflictRequestException : MalformedRequestException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ConflictRequestException"/> class for a resource and attempted status.
    /// </summary>
    /// <param name="resourceType">The type of resource in conflict.</param>
    /// <param name="attemptedStatus">The status that was attempted.</param>
    private ConflictRequestException(string resourceType, string attemptedStatus)
        : base($"The {resourceType} could not be set to the status of '{attemptedStatus}'")
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="ConflictRequestException"/> class for a resource, expected status, and actual status.
    /// </summary>
    /// <param name="resourceType">The type of resource in conflict.</param>
    /// <param name="expectedStatus">The expected status.</param>
    /// <param name="actualStatus">The actual status.</param>
    private ConflictRequestException(string resourceType, string expectedStatus, string actualStatus)
        : base($"The {resourceType} used in this request did not have the expected status '{expectedStatus}' but had '{actualStatus}'.")
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="ConflictRequestException"/> class for an account with a conflicting status.
    /// </summary>
    /// <param name="attemptedStatus">The attempted account status.</param>
    public ConflictRequestException(AccountStatus attemptedStatus)
        : this("account", $"{attemptedStatus}")
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="ConflictRequestException"/> class for a challenge with a conflicting status.
    /// </summary>
    /// <param name="attemptedStatus">The attempted challenge status.</param>
    public ConflictRequestException(ChallengeStatus attemptedStatus)
        : this("challenge", $"{attemptedStatus}")
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="ConflictRequestException"/> class for an account with expected and actual statuses.
    /// </summary>
    /// <param name="expectedStatus">The expected account status.</param>
    /// <param name="actualStatus">The actual account status.</param>
    public ConflictRequestException(AccountStatus expectedStatus, AccountStatus actualStatus)
        : this("account", $"{expectedStatus}", $"{actualStatus}")
    { }

    /// <summary>
    /// Initializes a new instance of the <see cref="ConflictRequestException"/> class for an order with expected and actual statuses.
    /// </summary>
    /// <param name="expectedStatus">The expected order status.</param>
    /// <param name="actualStatus">The actual order status.</param>
    public ConflictRequestException(OrderStatus expectedStatus, OrderStatus actualStatus)
        : this("order", $"{expectedStatus}", $"{actualStatus}")
    { }
}
