﻿namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using Exceptions;
using Extensions;

[Serializable]
public sealed class Authorization : ISerializable
{
    private static readonly Dictionary<AuthorizationStatus, AuthorizationStatus[]> ValidStatusTransitions = new()
    {
        {
            AuthorizationStatus.Pending,
            [AuthorizationStatus.Invalid, AuthorizationStatus.Expired, AuthorizationStatus.Valid]
        },
        {
            AuthorizationStatus.Valid,
            [AuthorizationStatus.Revoked, AuthorizationStatus.Deactivated, AuthorizationStatus.Expired]
        }
    };

    private Order? _order;

    public Authorization(Order order, Identifier identifier, DateTimeOffset expires)
    {
        AuthorizationId = GuidString.NewValue();
        Challenges = [];

        Order = order ?? throw new ArgumentNullException(nameof(order));
        Order.Authorizations.Add(this);

        Identifier = identifier ?? throw new ArgumentNullException(nameof(identifier));
        Expires = expires;
    }

    public string AuthorizationId { get; }
    public AuthorizationStatus Status { get; set; }

    public Order Order
    {
        get { return _order ?? throw new NotInitializedException(); }
        internal set { _order = value; }
    }

    public Identifier Identifier { get; }
    public bool IsWildcard
    {
        get { return Identifier.IsWildcard; }
    }

    public DateTimeOffset Expires { get; set; }

    public List<Challenge> Challenges { get; private set; }
        

    public Challenge? GetChallenge(string challengeId)
        => Challenges.FirstOrDefault(x => x.ChallengeId == challengeId);

    public void SelectChallenge(Challenge challenge)
        => Challenges.RemoveAll(c => c != challenge);

    public void ClearChallenges()
        => Challenges.Clear();


    public void SetStatus(AuthorizationStatus nextStatus)
    {
        if (!ValidStatusTransitions.ContainsKey(Status))
        {
            throw new InvalidOperationException($"Cannot do challenge status transition from '{Status}'.");
        }

        if (!ValidStatusTransitions[Status].Contains(nextStatus))
        {
            throw new InvalidOperationException($"Cannot do challenge status transition from '{Status}' to {nextStatus}.");
        }

        Status = nextStatus;
    }



    // --- Serialization Methods --- //

    private Authorization(SerializationInfo info, StreamingContext streamingContext)
    {
        if (info is null)
        {
            throw new ArgumentNullException(nameof(info));
        }

        AuthorizationId = info.GetRequiredString(nameof(AuthorizationId));
        Status = Enum.Parse<AuthorizationStatus>(info.GetString(nameof(Status))!); //(AuthorizationStatus)info.GetInt32(nameof(Status));

        Identifier = info.GetRequiredValue<Identifier>(nameof(Identifier));
        Expires = info.GetValue<DateTimeOffset>(nameof(Expires));

        Challenges = info.GetRequiredValue<List<Challenge>>(nameof(Challenges));
        foreach (var challenge in Challenges)
        {
            challenge.Authorization = this;
        }
    }

    public void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        if (info is null)
        {
            throw new ArgumentNullException(nameof(info));
        }

        info.AddValue("SerializationVersion", 1);

        info.AddValue(nameof(AuthorizationId), AuthorizationId);
        info.AddValue(nameof(Status), Status);
            
        info.AddValue(nameof(Identifier), Identifier);
        info.AddValue(nameof(Expires), Expires);
            
        info.AddValue(nameof(Challenges), Challenges);
    }
}