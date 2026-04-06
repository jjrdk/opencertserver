using CertesSlim.Acme.Resource;
using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Represents an ACME authorization, which binds an identifier to an account and tracks challenge status.
/// </summary>
public sealed class Authorization
{
    private static readonly Dictionary<AuthorizationStatus, AuthorizationStatus[]> ValidStatusTransitions = new()
    {
        {
            AuthorizationStatus.Pending,
            [AuthorizationStatus.Invalid, AuthorizationStatus.Expired, AuthorizationStatus.Valid, AuthorizationStatus.Deactivated]
        },
        {
            AuthorizationStatus.Valid,
            [AuthorizationStatus.Revoked, AuthorizationStatus.Deactivated, AuthorizationStatus.Expired]
        }
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="Authorization"/> class for the specified order, identifier, and expiration.
    /// </summary>
    /// <param name="order">The order to which this authorization belongs.</param>
    /// <param name="identifier">The identifier being authorized.</param>
    /// <param name="expires">The expiration date/time for the authorization.</param>
    public Authorization(Order order, Identifier identifier, DateTimeOffset expires)
    {
        AuthorizationId = GuidString.NewValue();
        Challenges = [];

        Order = order ?? throw new ArgumentNullException(nameof(order));
        Order.Authorizations.Add(this);

        Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
        Expires = expires;
    }

    /// <summary>
    /// Gets the unique authorization identifier.
    /// </summary>
    public string AuthorizationId { get; }

    /// <summary>
    /// Gets or sets the current status of the authorization.
    /// </summary>
    public AuthorizationStatus Status { get; set; }

    /// <summary>
    /// Gets the order to which this authorization belongs.
    /// </summary>
    public Order Order
    {
        get { return field ?? throw new NotInitializedException(); }
        internal set;
    }

    /// <summary>
    /// Gets the identifier being authorized.
    /// </summary>
    public Identifier Identifier { get; }

    /// <summary>
    /// Gets a value indicating whether the identifier is a wildcard.
    /// </summary>
    public bool IsWildcard
    {
        get { return Identifier.IsWildcard; }
    }

    /// <summary>
    /// Gets or sets the expiration date/time for the authorization.
    /// </summary>
    public DateTimeOffset Expires { get; set; }

    /// <summary>
    /// Gets the list of challenges associated with this authorization.
    /// </summary>
    public List<Challenge> Challenges { get; private set; }


    /// <summary>
    /// Gets the challenge with the specified challenge ID, or null if not found.
    /// </summary>
    /// <param name="challengeId">The challenge identifier.</param>
    /// <returns>The matching <see cref="Challenge"/>, or null if not found.</returns>
    public Challenge? GetChallenge(string challengeId)
        => Challenges.FirstOrDefault(x => x.ChallengeId == challengeId);

    /// <summary>
    /// Selects a single challenge for this authorization, removing all others.
    /// </summary>
    /// <param name="challenge">The challenge to select.</param>
    public void SelectChallenge(Challenge challenge)
        => Challenges.RemoveAll(c => c != challenge);

    /// <summary>
    /// Removes all challenges from this authorization.
    /// </summary>
    public void ClearChallenges()
        => Challenges.Clear();


    /// <summary>
    /// Sets the status of the authorization, enforcing valid status transitions.
    /// </summary>
    /// <param name="nextStatus">The next status to set.</param>
    /// <exception cref="InvalidOperationException">Thrown if the status transition is not allowed.</exception>
    public void SetStatus(AuthorizationStatus nextStatus)
    {
        if (!ValidStatusTransitions.TryGetValue(Status, out var transition))
        {
            throw new InvalidOperationException($"Cannot do challenge status transition from '{Status}'.");
        }

        if (!transition.Contains(nextStatus))
        {
            throw new InvalidOperationException(
                $"Cannot do challenge status transition from '{Status}' to {nextStatus}.");
        }

        Status = nextStatus;
    }
}
