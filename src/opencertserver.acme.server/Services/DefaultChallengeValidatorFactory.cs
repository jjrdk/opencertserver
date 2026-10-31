using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Linq;
using Abstractions.Model;
using Abstractions.Services;

/// <summary>
/// Routes an <see cref="Challenge"/> to the <see cref="IValidateChallenges"/> whose
/// <see cref="IValidateChallenges.AppliesTo"/> matches <see cref="Challenge.Type"/>. The per-type marker
/// interfaces were removed in favour of this single discriminator, so all challenge validators are registered
/// as <see cref="IValidateChallenges"/> and resolved as a collection.
/// </summary>
public sealed class DefaultChallengeValidatorFactory : IChallengeValidatorFactory
{
    private readonly IReadOnlyList<IValidateChallenges> _validators;

    public DefaultChallengeValidatorFactory(IEnumerable<IValidateChallenges> validators)
    {
        ArgumentNullException.ThrowIfNull(validators);
        _validators = validators.ToList();
    }

    public IValidateChallenges GetValidator(Challenge challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);

        var validator = _validators.FirstOrDefault(v => v.AppliesTo == challenge.Type);
        return validator ?? throw new InvalidOperationException("Unknown Challenge Type");
    }
}
