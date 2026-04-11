namespace OpenCertServer.Acme.Abstractions.Model;

using System;

/// <summary>
/// Represents an external account key provisioned out-of-band by the CA, used to bind
/// an ACME account to an existing external CA account (RFC 8555 §7.3.4).
/// </summary>
public sealed class ExternalAccountKey : IVersioned
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ExternalAccountKey"/> class.
    /// </summary>
    /// <param name="keyId">The key identifier issued by the CA.</param>
    /// <param name="macKey">The base64url-encoded HMAC MAC key issued by the CA.</param>
    /// <param name="macAlgorithm">The HMAC algorithm, e.g. "HS256", "HS384", or "HS512".</param>
    public ExternalAccountKey(string keyId, string macKey, string macAlgorithm = "HS256")
    {
        KeyId = keyId;
        MacKey = macKey;
        MacAlgorithm = macAlgorithm;
    }

    /// <summary>Gets the key identifier issued by the CA for out-of-band provisioning.</summary>
    public string KeyId { get; }

    /// <summary>Gets the base64url-encoded HMAC MAC key.</summary>
    public string MacKey { get; }

    /// <summary>Gets the HMAC algorithm, e.g. "HS256", "HS384", or "HS512".</summary>
    public string MacAlgorithm { get; }

    /// <summary>
    /// Gets a value indicating whether this key has already been consumed by a successful account creation.
    /// EAB keys are single-use; once bound, they must not be accepted again.
    /// </summary>
    public bool IsUsed { get; private set; }

    /// <summary>Gets the account ID that this key was bound to, or null if not yet bound.</summary>
    public string? BoundAccountId { get; private set; }

    /// <summary>Gets the UTC timestamp at which the key was bound, or null if not yet bound.</summary>
    public DateTimeOffset? BoundAt { get; private set; }

    /// <summary>
    /// Marks this key as used and records which account it was bound to.
    /// </summary>
    /// <param name="accountId">The account identifier.</param>
    public void MarkUsed(string accountId)
    {
        IsUsed = true;
        BoundAccountId = accountId;
        BoundAt = DateTimeOffset.UtcNow;
    }

    /// <inheritdoc />
    public long Version { get; set; }
}

