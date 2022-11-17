namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using Exceptions;
using Extensions;

[Serializable]
public sealed class Challenge : ISerializable
{
    private static readonly Dictionary<ChallengeStatus, ChallengeStatus[]> ValidStatusTransitions = 
        new()
        {
            { ChallengeStatus.Pending, new [] { ChallengeStatus.Processing } },
            { ChallengeStatus.Processing, new [] { ChallengeStatus.Processing, ChallengeStatus.Invalid, ChallengeStatus.Valid } }
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
        if (!ValidStatusTransitions.ContainsKey(Status))
        {
            throw new ConflictRequestException(nextStatus);
        }

        if (!ValidStatusTransitions[Status].Contains(nextStatus))
        {
            throw new ConflictRequestException(nextStatus);
        }

        Status = nextStatus;
    }



    // --- Serialization Methods --- //

    private Challenge(SerializationInfo info, StreamingContext streamingContext)
    {
        if (info is null)
        {
            throw new ArgumentNullException(nameof(info));
        }

        ChallengeId = info.GetRequiredString(nameof(ChallengeId));
        Status = Enum.Parse<ChallengeStatus>(info.GetString(nameof(Status))!); //(ChallengeStatus)info.GetInt32(nameof(Status));

        Type = info.GetRequiredString(nameof(Type));
        Token = info.GetRequiredString(nameof(Token));

        Validated = info.TryGetValue<DateTimeOffset?>(nameof(Validated));
        Error = info.TryGetValue<AcmeError?>(nameof(Error));
    }

    public void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        if (info is null)
        {
            throw new ArgumentNullException(nameof(info));
        }

        info.AddValue("SerializationVersion", 1);

        info.AddValue(nameof(ChallengeId), ChallengeId);
        info.AddValue(nameof(Status), Status);

        info.AddValue(nameof(Type), Type);
        info.AddValue(nameof(Token), Token);

        info.AddValue(nameof(Validated), Validated);
        info.AddValue(nameof(Error), Error);
    }
}