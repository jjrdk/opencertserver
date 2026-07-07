using System.Text.Json.Serialization;

namespace OpenCertServer.Attestation.Config;

public record AttestationConfig
{
    public GlobalSettings Global { get; init; } = new();
    public Dictionary<string, ProviderSettings> Providers { get; init; } = new();
}

public record GlobalSettings
{
    public string CloudContext { get; init; } = "Local";
}

public record ProviderSettings
{
    public string? PccsUrl { get; init; }
    public string? VpsUrl { get; init; }
    public string? VerifyUrl { get; init; }
    public string? RootCA { get; init; }
    public string? TeamId { get; init; }
    public string? AppId { get; init; }
}
