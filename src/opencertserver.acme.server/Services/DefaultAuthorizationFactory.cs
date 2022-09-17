namespace OpenCertServer.Acme.Server.Services
{
    using System;
    using Abstractions.Model;
    using Abstractions.Services;

    public sealed class DefaultAuthorizationFactory : IAuthorizationFactory
    {
        public void CreateAuthorizations(Order order)
        {
            if (order is null)
            {
                throw new ArgumentNullException(nameof(order));
            }

            foreach (var authorization in order.Identifiers.Select(
                         identifier => new Authorization(order, identifier, DateTimeOffset.UtcNow.AddDays(2))))
            {
                CreateChallenges(authorization);
            }
        }

        private static void CreateChallenges(Authorization authorization)
        {
            _ = new Challenge(authorization, ChallengeTypes.Dns01);
            if (!authorization.IsWildcard)
            {
                _ = new Challenge(authorization, ChallengeTypes.Http01);
            }
        }
    }
}
