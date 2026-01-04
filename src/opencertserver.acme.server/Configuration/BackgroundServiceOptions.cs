namespace OpenCertServer.Acme.Server.Configuration;

public record BackgroundServiceOptions
{
    public bool EnableValidationService { get; set; } = true;

    public bool EnableIssuanceService { get; set; }

    public int ValidationCheckInterval { get; set; } = 1;

    public int IssuanceCheckInterval { get; set; } = 1;
}
