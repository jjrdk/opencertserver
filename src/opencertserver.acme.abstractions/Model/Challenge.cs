using CertesSlim.Acme.Resource;
using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using System.Collections.Generic;

/// <summary>
/// Represents an ACME challenge, which is used to prove control over an identifier as part of the ACME protocol.
/// </summary>
public sealed class Challenge
{
    private static readonly Dictionary<ChallengeStatus, ChallengeStatus[]> ValidStatusTransitions =
        new()
        {
            { ChallengeStatus.Pending, [ChallengeStatus.Processing] },
            { ChallengeStatus.Processing, [ChallengeStatus.Processing, ChallengeStatus.Invalid, ChallengeStatus.Valid] }
        };

    /// <summary>
    /// Initializes a new instance of the <see cref="Challenge"/> class for the specified authorization and challenge type.
    /// </summary>
    /// <param name="authorization">The parent authorization to which this challenge belongs.</param>
    /// <param name="type">The challenge type (e.g., http-01, dns-01).</param>
    /// <exception cref="InvalidOperationException">Thrown if the challenge type is not supported.</exception>
    public Challenge(Authorization authorization, string type)
    {
        if (!ChallengeTypes.AllTypes.Contains(type))
        {
            throw new InvalidOperationException($"Unknown ChallengeType {type}");
        }

        ChallengeId = GuidString.NewValue();

        Type = type;
        Token = CryptoString.NewValue();

        Authorization = authorization;
        Authorization.Challenges.Add(this);
    }

    /// <summary>
    /// Gets the unique challenge identifier.
    /// </summary>
    public string ChallengeId { get; }

    /// <summary>
    /// Gets or sets the current status of the challenge.
    /// </summary>
    public ChallengeStatus Status { get; set; }

    /// <summary>
    /// Gets the challenge type (e.g., http-01, dns-01).
    /// </summary>
    public string Type { get; }

    /// <summary>
    /// Gets the challenge token value.
    /// </summary>
    public string Token { get; }

    /// <summary>
    /// Gets the parent authorization to which this challenge belongs.
    /// </summary>
    public Authorization Authorization
    {
        get { return field ?? throw new NotInitializedException(); }
        internal set;
    }

    /// <summary>
    /// Gets or sets the date/time when the challenge was validated, if any.
    /// </summary>
    public DateTimeOffset? Validated { get; set; }

    /// <summary>
    /// Gets a value indicating whether the challenge is valid (i.e., has been validated).
    /// </summary>
    public bool IsValid
    {
        get { return Validated.HasValue; }
    }

    /// <summary>
    /// Gets or sets the error object associated with the challenge, if any.
    /// </summary>
    public AcmeError? Error { get; set; }

    /// <summary>
    /// Sets the status of the challenge, enforcing valid status transitions.
    /// </summary>
    /// <param name="nextStatus">The next status to set.</param>
    /// <exception cref="ConflictRequestException">Thrown if the status transition is not allowed.</exception>
    public void SetStatus(ChallengeStatus nextStatus)
    {
        if (!ValidStatusTransitions.TryGetValue(Status, out var transition) || !transition.Contains(nextStatus))
        {
            throw new ConflictRequestException(nextStatus);
        }

        Status = nextStatus;
    }
}
