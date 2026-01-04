using CertesSlim.Acme;
using CertesSlim.Acme.Resource;

namespace CertesSlim.Extensions;

/// <summary>
/// Extension methods for <see cref="IAuthorizationContext"/>.
/// </summary>
public static class IAuthorizationContextExtensions
{
    /// <param name="authorizationContext">The authorization context.</param>
    extension(IAuthorizationContext authorizationContext)
    {
        /// <summary>
        /// Gets the HTTP challenge.
        /// </summary>
        /// <returns>The HTTP challenge, <c>null</c> if no HTTP challenge available.</returns>
        public Task<IChallengeContext?> Http() =>
            authorizationContext.Challenge(ChallengeTypes.Http01);

        /// <summary>
        /// Gets the DNS challenge.
        /// </summary>
        /// <returns>The DNS challenge, <c>null</c> if no DNS challenge available.</returns>
        public Task<IChallengeContext?> Dns() =>
            authorizationContext.Challenge(ChallengeTypes.Dns01);

        /// <summary>
        /// Gets the TLS ALPN challenge.
        /// </summary>
        /// <returns>The TLS ALPN challenge, <c>null</c> if no TLS ALPN challenge available.</returns>
        public Task<IChallengeContext?> TlsAlpn() =>
            authorizationContext.Challenge(ChallengeTypes.TlsAlpn01);

        /// <summary>
        /// Gets a challenge by type.
        /// </summary>
        /// <param name="type">The challenge type.</param>
        /// <returns>The challenge, <c>null</c> if no challenge found.</returns>
        public async Task<IChallengeContext?> Challenge(string type)
        {
            var challenges = await authorizationContext.Challenges();
            return challenges.FirstOrDefault(c => c.Type == type);
        }
    }
}
