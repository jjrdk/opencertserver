namespace OpenCertServer.Acme.Abstractions.Exceptions;

using CertesSlim.Acme.Resource;

/// <summary>
/// Describes a single identifier that was rejected for an ACME order, together with
/// the human-readable reason it was rejected.
/// </summary>
public sealed record RejectedIdentifier(Identifier Identifier, string Reason);
