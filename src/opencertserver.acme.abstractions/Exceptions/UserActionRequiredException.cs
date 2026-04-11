namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when a client must take a manual action before the server can continue.
/// Per RFC 8555 §7.3.3, this is used when the server's terms of service have been updated
/// since the account last agreed, requiring the client to re-agree before creating new orders.
/// </summary>
public sealed class UserActionRequiredException : AcmeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserActionRequiredException"/> class.
    /// </summary>
    /// <param name="message">The message that describes the error condition.</param>
    /// <param name="tosUrl">
    /// The URL of the current terms of service to include in the <c>Link</c> response header,
    /// or <c>null</c> if no terms-of-service URL is available.
    /// </param>
    public UserActionRequiredException(string message, string? tosUrl = null)
        : base(message)
    {
        TosUrl = tosUrl;
    }

    /// <summary>
    /// Gets the URL of the current terms of service, if available.
    /// When set, the server MUST include a <c>Link: &lt;url&gt;; rel="terms-of-service"</c>
    /// header in the error response (RFC 8555 §7.3.3).
    /// </summary>
    public string? TosUrl { get; }

    /// <inheritdoc/>
    public override string ErrorType => "userActionRequired";
}

