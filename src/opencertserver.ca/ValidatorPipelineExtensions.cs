namespace OpenCertServer.Ca;

using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// Per-validator settings, bound from the <c>Validators__&lt;Name&gt;</c> configuration section.
/// </summary>
public sealed class ValidatorSettings
{
    /// <summary>When <c>false</c>, the validator is skipped.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Override the validator's phase (config <c>Validators__&lt;Name&gt;__Phase</c>).</summary>
    public ValidatorPhase? Phase { get; set; }

    /// <summary>Override the validator's order within its phase (config <c>Validators__&lt;Name&gt;__Order</c>).</summary>
    public int? Order { get; set; }
}

/// <summary>
/// The <c>Validators</c> configuration section. Controls the phase order (<c>Validators__Phases</c>) and per-validator
/// settings (<c>Validators__&lt;Name&gt;__Enabled</c> / <c>__Phase</c> / <c>__Order</c>).
/// </summary>
public sealed class ValidatorOptions
{
    /// <summary>The phase order (config <c>Validators__Phases</c>). Defaults to the canonical fixed order.</summary>
    public IReadOnlyList<ValidatorPhase> Phases { get; set; } = ValidatorPipeline.DefaultPhaseOrder;

    /// <summary>Per-validator settings, keyed by the validator name (config <c>Validators__&lt;Name&gt;</c>).</summary>
    public Dictionary<string, ValidatorSettings> Validators { get; set; } = new();
}

/// <summary>
/// DI helpers that build the <see cref="IValidatorPipeline"/> and register request validators with a phase and order.
/// </summary>
public static class ValidatorPipelineExtensions
{
    /// <summary>
    /// Register a validator type <typeparamref name="TValidator"/> into the pipeline at <paramref name="phase"/>
    /// (config name defaults to the type name). The validator is resolved from DI, so its constructor dependencies must
    /// be registered (e.g. <c>services.AddSingleton&lt;TValidator&gt;()</c>) before calling this. For parameterless
    /// validators with operator options, use the <see cref="AddValidator{TValidator}(IServiceCollection, ValidatorPhase,
    /// int, Action{TValidator}, string?)"/> overload. Call <see cref="AddValidatorPipeline"/> to assemble the pipeline.
    /// </summary>
    public static IServiceCollection AddValidator<TValidator>(
        this IServiceCollection services,
        ValidatorPhase phase,
        int order = 0,
        string? name = null)
        where TValidator : class, IValidateCertificateRequests
    {
        var registrationName = name ?? typeof(TValidator).Name;
        services.AddSingleton(sp =>
            new ValidatorRegistration(registrationName, phase, order, sp.GetRequiredService<TValidator>()));
        return services;
    }

    /// <summary>
    /// Register a validator with a parameterless constructor, applying <paramref name="configure"/> (operator "options"),
    /// into the pipeline at <paramref name="phase"/>. Use this for simple validators that do not need DI.
    /// </summary>
    public static IServiceCollection AddValidator<TValidator>(
        this IServiceCollection services,
        ValidatorPhase phase,
        int order,
        Action<TValidator> configure,
        string? name = null)
        where TValidator : class, IValidateCertificateRequests, new()
    {
        services.AddSingleton(sp =>
        {
            var validator = new TValidator();
            configure(validator);
            return validator;
        });

        var registrationName = name ?? typeof(TValidator).Name;
        services.AddSingleton(sp =>
            new ValidatorRegistration(registrationName, phase, order, sp.GetRequiredService<TValidator>()));
        return services;
    }

    /// <summary>
    /// Register an <see cref="IValidateCertificateRequests"/> validator at <paramref name="phase"/> with the given
    /// <paramref name="order"/>.
    /// </summary>
    public static IServiceCollection AddCertificateRequestValidator<TValidator>(
        this IServiceCollection services,
        string name,
        ValidatorPhase phase,
        int order)
        where TValidator : IValidateCertificateRequests
    {
        services.AddSingleton(sp =>
            new ValidatorRegistration(
                name,
                phase,
                order,
                sp.GetRequiredService<TValidator>()));
        return services;
    }

    /// <summary>
    /// Assemble the <see cref="IValidatorPipeline"/> from all registered <see cref="ValidatorRegistration"/>s, applying
    /// <paramref name="options"/> (phase order, per-validator <c>Enabled</c> / <c>Phase</c> / <c>Order</c>) when
    /// supplied. Call this after registering the validators.
    /// </summary>
    public static IServiceCollection AddValidatorPipeline(this IServiceCollection services, ValidatorOptions? options = null)
    {
        services.AddSingleton<IValidatorPipeline>(sp =>
        {
            // The default pipeline is built from the registered request validators (the five historical validators,
            // in registration order) plus any operator-added validators (via AddValidator<T>).
            var registrations = new List<ValidatorRegistration>();
            var defaults = sp.GetServices<IValidateCertificateRequests>().ToArray();
            if (defaults.Length > 0)
            {
                registrations.AddRange(ValidatorPipeline.FromCertificateRequestRegistrations(defaults));
            }

            registrations.AddRange(sp.GetServices<ValidatorRegistration>());
            var phaseOrder = options?.Phases ?? ValidatorPipeline.DefaultPhaseOrder;
            return ValidatorPipeline.Create(phaseOrder, ApplyOptions(registrations, options));
        });
        return services;
    }

    private static ValidatorRegistration[] ApplyOptions(List<ValidatorRegistration> registrations, ValidatorOptions? options)
    {
        if (options is null)
        {
            return registrations.ToArray();
        }

        var result = new List<ValidatorRegistration>(registrations.Count);
        foreach (var registration in registrations)
        {
            if (options.Validators.TryGetValue(registration.Name, out var settings))
            {
                if (!settings.Enabled)
                {
                    continue;
                }

                result.Add(registration with
                {
                    Phase = settings.Phase ?? registration.Phase,
                    Order = settings.Order ?? registration.Order,
                });
            }
            else
            {
                result.Add(registration);
            }
        }

        return result.ToArray();
    }
}
