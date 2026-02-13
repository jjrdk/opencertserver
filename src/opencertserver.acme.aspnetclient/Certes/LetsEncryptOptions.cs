using CertesSlim.Extensions;
using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using System.Collections.Generic;
using global::CertesSlim.Acme;

public abstract class AcmeOptions
{
    public string[] Domains { get; init; } = [];

    /// <summary>
    /// Used only for LetsEncrypt to contact you when the domain is about to expire - not actually validated.
    /// </summary>
    public string Email { get; init; } = null!;

    /// <summary>
    /// The amount of time before the expiry date of the certificate that a new one is created. Defaults to 30 days.
    /// </summary>
    public TimeSpan? TimeUntilExpiryBeforeRenewal { get; init; } = TimeSpan.FromDays(30);

    /// <summary>
    /// The amount of time after the last renewal date that a new one is created. Defaults to null.
    /// </summary>
    public TimeSpan? TimeAfterIssueDateBeforeRenewal { get; init; }

    /// <summary>
    /// Recommended while testing - increases your rate limit towards LetsEncrypt. Defaults to false.
    /// </summary>
    public bool UseStaging { get; init; }

    /// <summary>
    /// Gets the uri which will be used to talk to LetsEncrypt servers.
    /// </summary>
    public abstract Uri AcmeServerUri { get; }

    /// <summary>
    /// Required. Sent to LetsEncrypt to let them know what details you want in your certificate. Some of the properties are optional.
    /// </summary>
    public required CsrInfo CertificateSigningRequest { get; init; }

    /// <summary>
    /// Gets or sets the renewal fail mode - i.e. what happens if an exception is thrown in the certificate renewal process.
    /// </summary>
    public RenewalFailMode RenewalFailMode { get; set; } = RenewalFailMode.LogAndContinue;

    /// <summary>
    /// Gets or sets the <see cref="KeyAlgorithm"/> used to request a new LetsEncrypt certificate.
    /// </summary>
    public string KeyAlgorithm { get; init; } = SecurityAlgorithms.EcdsaSha256;

    /// <summary>
    /// Get or set a delay before the initial run of the renewal service (subsequent runs will be at 1hr intervals)
    /// On some platform/deployment systems (e.g Azure Slot Swap) we do not want the renewal service to start immediately, because we may not
    /// yet have incoming requests (e.g. for challenges) directed to us.
    /// </summary>
    public TimeSpan RenewalServiceStartupDelay { get; set; } = TimeSpan.Zero;
}

public sealed class LetsEncryptOptions : AcmeOptions
{
    /// <summary>
    /// Gets the uri which will be used to talk to LetsEncrypt servers.
    /// </summary>
    public override Uri AcmeServerUri
    {
        get { return UseStaging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2; }
    }
}
