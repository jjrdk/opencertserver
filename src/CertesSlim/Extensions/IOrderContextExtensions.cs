using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using CertesSlim.Pkcs;
using CertesSlim.Properties;

namespace CertesSlim.Extensions;

/// <summary>
/// Extension methods for <see cref="IOrderContext"/>.
/// </summary>
public static class IOrderContextExtensions
{
    /// <param name="context">The order context.</param>
    extension(IOrderContext context)
    {
        /// <summary>
        /// Finalizes the certificate order.
        /// </summary>
        /// <param name="csr">The CSR.</param>
        /// <param name="key">The private key for the certificate.</param>
        /// <returns>
        /// The order finalized.
        /// </returns>
        public async Task<Order> Finalize(CsrInfo csr, IKey key)
        {
            var builder = await context.CreateCsr(key);

            foreach (var (name, value) in csr.Fields)
            {
                builder.AddName(name, value);
            }

            if (string.IsNullOrWhiteSpace(csr.CommonName))
            {
                builder.AddName("CN", builder.SubjectAlternativeNames[0]);
            }

            return await context.Finalize(builder.Generate());
        }

        /// <summary>
        /// Creates CSR from the order.
        /// </summary>
        /// <param name="key">The private key.</param>
        /// <returns>The CSR.</returns>
        public async Task<CertificationRequestBuilder> CreateCsr(IKey key)
        {
            var builder = new CertificationRequestBuilder(key);
            var order = await context.Resource();
            foreach (var identifier in order.Identifiers!)
            {
                builder.SubjectAlternativeNames.Add(identifier.Value);
            }

            return builder;
        }

        /// <summary>
        /// Finalizes and download the certifcate for the order.
        /// </summary>
        /// <param name="csr">The CSR.</param>
        /// <param name="key">The private key for the certificate.</param>
        /// <param name="retryCount">Number of retries when the Order is in 'processing' state. (default = 1)</param>
        /// <param name="preferredChain">The preferred Root Certificate.</param>
        /// <returns>
        /// The certificate generated.
        /// </returns>
        public async Task<CertificateChain> Generate(CsrInfo csr, IKey key, string? preferredChain = null, int retryCount = 1)
        {
            var order = await context.Resource();
            if (order.Status != OrderStatus.Ready && // draft-11
                order.Status != OrderStatus.Pending) // pre draft-11
            {
                throw new AcmeException(string.Format(Strings.ErrorInvalidOrderStatusForFinalize, order.Status));
            }

            order = await context.Finalize(csr, key);

            while (order.Status == OrderStatus.Processing && retryCount-- > 0)
            {
                await Task.Delay(context.RetryAfter);
                order = await context.Resource();
            }

            if (order.Status != OrderStatus.Valid)
            {
                throw new AcmeException(Strings.ErrorFinalizeFailed);
            }

            return await context.Download(preferredChain);
        }

        /// <summary>
        /// Gets the authorization by identifier.
        /// </summary>
        /// <param name="value">The identifier value.</param>
        /// <param name="type">The identifier type.</param>
        /// <returns>The authorization found.</returns>
        public async Task<IAuthorizationContext?> Authorization(string value, IdentifierType type = IdentifierType.Dns)
        {
            var wildcard = value.StartsWith("*.");
            if (wildcard)
            {
                value = value[2..];
            }

            foreach (var authzCtx in await context.Authorizations())
            {
                var authz = await authzCtx.Resource();
                if (string.Equals(authz.Identifier?.Value, value, StringComparison.OrdinalIgnoreCase) &&
                    wildcard == authz.Wildcard.GetValueOrDefault() &&
                    authz.Identifier?.Type == type)
                {
                    return authzCtx;
                }
            }

            return null;
        }
    }
}
