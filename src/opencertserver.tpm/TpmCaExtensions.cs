namespace OpenCertServer.Tpm;

using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Extension methods for registering TPM-backed CA services.
/// </summary>
public static class TpmCaExtensions
{
    /// <summary>
    /// Registers a TPM-backed certificate authority to the service collection.
    /// Two CA profiles are created: RSA-2048 (<see cref="TpmCaOptions.RsaKeyHandle"/>) and
    /// P-256 ECDsa (<see cref="TpmCaOptions.EcDsaKeyHandle"/>). TPM keys are provisioned once
    /// at fixed persistent handles; public certificates are stored in the OS certificate store
    /// scoped to the running user account.
    /// </summary>
    public static IServiceCollection AddTpmCertificateAuthority(
        this IServiceCollection services,
        Action<TpmCaOptions> configureOptions,
        string[]? ocspUrls = null,
        string[]? crlUrls = null,
        string[]? caIssuersUrls = null,
        IValidateX509Chains? chainValidation = null,
        bool strictOcspHttpBinding = false)
    {
        var options = new TpmCaOptions();
        configureOptions(options);

        services.AddSingleton(options);
        services.AddSingleton<ITpmKeyProvider>(sp => new TssTpmKeyProvider(sp.GetRequiredService<TpmCaOptions>()));
        services.AddSingleton<TpmCaProfileFactory>(sp => new TpmCaProfileFactory(
            sp.GetRequiredService<TpmCaOptions>(),
            sp.GetRequiredService<ITpmKeyProvider>()));

        services.AddSingleton<IStoreCaProfiles>(sp =>
        {
            var factory = sp.GetRequiredService<TpmCaProfileFactory>();
            var rsaProfile = factory.CreateOrLoadRsaProfile("default");
            var ecdsaProfile = factory.CreateOrLoadEcDsaProfile("ecdsa");
            return new CaProfileSet("default", rsaProfile, ecdsaProfile);
        });

        services.AddSingleton<CaConfiguration>(sp =>
            new CaConfiguration(
                sp.GetRequiredService<IStoreCaProfiles>(),
                ocspUrls ?? [],
                crlUrls ?? [],
                caIssuersUrls ?? [],
                strictOcspHttpBinding));

        services.AddSingleton<IValidateOcspRequest, OcspRequestSignatureValidator>();
        services.AddSingleton<ICertificateAuthority>(sp =>
            new CertificateAuthority(
                sp.GetRequiredService<CaConfiguration>(),
                sp.GetRequiredService<IStoreCertificates>(),
                chainValidation ?? new AcceptAllX509Chains(),
                sp.GetRequiredService<ILogger<CertificateAuthority>>(),
                sp.GetServices<IValidateCertificateRequests>().ToArray()));

        return services;
    }

    /// <summary>
    /// Default chain validation strategy that accepts all X.509 chains.
    /// Used when no custom <see cref="IValidateX509Chains"/> is provided.
    /// </summary>
    private sealed class AcceptAllX509Chains : IValidateX509Chains
    {
        public Task<bool> Validate(X509Chain chain, CancellationToken cancellationToken = default)
            => Task.FromResult(true);
    }
}

