namespace OpenCertServer.Acme.Abstractions.Model;

/// <summary>
/// Represents an ACME nonce, a unique token used to prevent replay attacks in the protocol.
/// </summary>
public record Nonce(string Token);
