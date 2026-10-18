namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>Rejects another evidence submission after a device challenge nonce has been consumed.</summary>
public sealed class AttestationReplayException() : AcmeException("This attestation nonce has already been consumed")
{
    /// <inheritdoc />
    public override string ErrorType => "replay_nonce";
}
