using CertesSlim.Acme.Resource;
using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using System.Collections.Generic;

public sealed class Challenge
{
    private static readonly Dictionary<ChallengeStatus, ChallengeStatus[]> ValidStatusTransitions =
        new()
        {
            { ChallengeStatus.Pending, [ChallengeStatus.Processing] },
            { ChallengeStatus.Processing, [ChallengeStatus.Processing, ChallengeStatus.Invalid, ChallengeStatus.Valid] }
        };

    private Authorization? _authorization;

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

    public string ChallengeId { get; }
    public ChallengeStatus Status { get; set; }

    public string Type { get; }
    public string Token { get; }

    public Authorization Authorization
    {
        get { return _authorization ?? throw new NotInitializedException(); }
        internal set { _authorization = value; }
    }

    public DateTimeOffset? Validated { get; set; }

    public bool IsValid
    {
        get { return Validated.HasValue; }
    }

    public AcmeError? Error { get; set; }


    public void SetStatus(ChallengeStatus nextStatus)
    {
        if (!ValidStatusTransitions.TryGetValue(Status, out var transition) || !transition.Contains(nextStatus))
        {
            throw new ConflictRequestException(nextStatus);
        }

        Status = nextStatus;
    }
}
