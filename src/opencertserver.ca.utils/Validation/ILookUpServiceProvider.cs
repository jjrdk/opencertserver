namespace OpenCertServer.Ca.Utils.Validation;

/// <summary>
/// Resolves the set of <em>acceptable reference identifiers</em> for a service a client is trying to
/// reach, independently of whatever a server presents, per RFC 9525 §4.3.1.
///
/// <para>
/// This is the sole external dependency of <see cref="CertificateIdentityValidator"/>, kept behind an
/// interface so the matcher can be unit-tested with a mock and a concrete implementation is out of
/// scope for this simple validator. A concrete implementation answers the "how do I know what this
/// service is allowed to be" question: it may expand a
/// <see cref="ServiceIdentifierType.Srv"/> reference to the host names a DNS/SRV record resolves to,
/// honor DNS <c>dNSName</c>/<c>URI-ID</c> forms, apply name constraints or public-suffix rules, or
/// consult an application service catalogue.
/// </para>
///
/// <para>
/// RFC 9525 deliberately does <em>not</em> decide which reference identifier a client selects — that is
/// the responsibility of the application protocol. This abstraction is where that decision (and any
/// service-catalogue / name-constraint policy) lives.
/// </para>
/// </summary>
public interface ILookUpServiceProvider
{
    /// <summary>
    /// Resolves the acceptable service identities for the requested service.
    /// </summary>
    /// <param name="reference">The service identity the client intends to reach.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The service identities to verify a presented certificate against. An empty result means the
    /// service resolves to no acceptable identifiers.
    /// </returns>
    Task<IReadOnlyList<ServiceIdentity>> ResolveServiceIdentities(
        ServiceIdentity reference,
        CancellationToken cancellationToken = default);
}
