namespace CertesSlim.Acme;

/// <summary>
/// <para>The well-known ACME servers. All endpoints on this list are compliant with RFC 8555.</para>
/// <para>Please note that different CAs have varying legal terms, pricing, and some difference in their ACME issuance policies. Consult each CA's documentation for more information.</para>
/// <para>Endpoints are defined at https://github.com/https-dev/docs/blob/master/list-of-acme-servers.md</para>
/// </summary>
public static class WellKnownServers
{
    /// <summary>
    /// Gets the URI for Let's Encrypt ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for Let's Encrypt ACME v2 production server.
    /// </value>
    public static Uri LetsEncryptV2 { get; } = new("https://acme-v02.api.letsencrypt.org/directory");

    /// <summary>
    /// Gets the URI for Let's Encrypt V2 staging server.
    /// </summary>
    /// <value>
    /// The URI for Let's Encrypt V2 staging server.
    /// </value>
    public static Uri LetsEncryptStagingV2 { get; } = new("https://acme-staging-v02.api.letsencrypt.org/directory");

    /// <summary>
    /// Gets the URI for ZeroSSL ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for ZeroSSL ACME v2 production server.
    /// </value>
    public static Uri ZeroSslV2 { get; } = new("https://acme.zerossl.com/v2/DV90");

    /// <summary>
    /// Gets the URI for Sectigo DV ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for Sectigo DV ACME v2 production server.
    /// </value>
    public static Uri SectigoDvV2 { get; } = new("https://acme.sectigo.com/v2/DV");

    /// <summary>
    /// Gets the URI for Sectigo OV ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for Sectigo OV ACME v2 production server.
    /// </value>
    public static Uri SectigoOvV2 { get; } = new("https://acme.sectigo.com/v2/OV");

    /// <summary>
    /// Gets the URI for Sectigo EV ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for Sectigo EV ACME v2 production server.
    /// </value>
    public static Uri SectigoEvV2 { get; } = new("https://acme.sectigo.com/v2/EV");

    /// <summary>
    /// Gets the URI for InCommon RSA OV ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for InCommon RSA OV ACME v2 production server.
    /// </value>
    public static Uri InCommonRsaOvV2 { get; } = new("https://acme.sectigo.com/v2/InCommonRSAOV");

    /// <summary>
    /// Gets the URI for InCommon ECC OV ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for InCommon ECC OV ACME v2 production server.
    /// </value>
    public static Uri InCommonEccOvV2 { get; } = new("https://acme.sectigo.com/v2/InCommonECCOV");

    /// <summary>
    /// Gets the URI for SSL.com DV RSA ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for SSL.com DV RSA ACME v2 production server.
    /// </value>
    public static Uri SslComDvRsaV2 { get; } = new("https://acme.ssl.com/sslcom-dv-rsa");

    /// <summary>
    /// Gets the URI for SSL.com DV ECC ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for SSL.com DV ECC ACME v2 production server.
    /// </value>
    public static Uri SslComDvEccV2 { get; } = new("https://acme.ssl.com/sslcom-dv-ecc");

    /// <summary>
    /// Gets the URI for Google Trust Services ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for Google Trust Services ACME v2 production server.
    /// </value>
    public static Uri GoogleTrustServicesV2 { get; } = new("https://dv.acme-v02.api.pki.goog/directory");

    /// <summary>
    /// Gets the URI for Google Trust Services ACME v2 test server.
    /// </summary>
    /// <value>
    /// The URI for Google Trust Services ACME v2 test server.
    /// </value>
    public static Uri GoogleTrustServicesTestV2 { get; } = new("https://dv.acme-v02.test-api.pki.goog/directory");

    /// <summary>
    /// Gets the URI for Actalis ACME v2 production server.
    /// </summary>
    /// <value>
    /// The URI for Actalis ACME v2 production server.
    /// </value>
    public static Uri ActalisV2 { get; } = new("https://acme-api.actalis.com/acme/directory");
}
