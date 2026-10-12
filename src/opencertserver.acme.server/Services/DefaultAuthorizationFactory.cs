using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Server.Services;

using System;
using Abstractions.Model;
using Abstractions.Services;

public sealed class DefaultAuthorizationFactory : IAuthorizationFactory
{
    private readonly IAttestationTrustProvider _trustProvider;

    public DefaultAuthorizationFactory(IAttestationTrustProvider trustProvider)
    {
        ArgumentNullException.ThrowIfNull(trustProvider);
        _trustProvider = trustProvider;
    }

    public void CreateAuthorizations(Order order)
    {
        ArgumentNullException.ThrowIfNull(order);

        foreach (var authorization in order.Identifiers.Select(
                     identifier => new Authorization(order, identifier, DateTimeOffset.UtcNow.AddDays(2))))
        {
            CreateChallenges(authorization);
        }
    }

    private void CreateChallenges(Authorization authorization)
    {
        _ = new Challenge(authorization, ChallengeTypes.Dns01);
        if (!authorization.IsWildcard)
        {
            _ = new Challenge(authorization, ChallengeTypes.Http01);
        }
        // Only offer device-attest-01 when explicit trusted roots are configured.
        // With an empty trust provider the validator rejects every attestation, so
        // advertising the challenge type would be misleading and confusing to clients.
        if (_trustProvider.GetTrustedRoots().Count > 0)
        {
            _ = new Challenge(authorization, ChallengeTypes.DeviceAttest01);
        }
    }
}

