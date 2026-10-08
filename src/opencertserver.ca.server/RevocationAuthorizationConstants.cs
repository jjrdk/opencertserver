namespace OpenCertServer.Ca.Server;

/// <summary>
/// Constants for revocation authorization policy and role names.
/// </summary>
public static class RevocationAuthorizationConstants
{
    /// <summary>
    /// The name of the ASP.NET Core authorization policy applied to the certificate revocation endpoint.
    /// Register a policy with this name via
    /// <c>services.AddAuthorization(o =&gt; o.AddPolicy(RevocationPolicyName, ...))</c>
    /// or call <see cref="Extensions.AddCertificateAuthorityAuthorization"/> for the default policy.
    /// </summary>
    public const string RevocationPolicyName = "ca_revoke";

    /// <summary>
    /// The role claim value that grants administrative permission to revoke any certificate in the CA,
    /// regardless of whether the caller is the subject of that certificate.
    /// Users without this role may only perform self-service revocation (revoking their own certificate).
    /// </summary>
    public const string CaAdminRole = "ca_admin";
}
