namespace OpenCertServer.Acme.Server.Configuration
{
    public record BackgroundServiceOptions
    {
        public bool EnableValidationService { get; set; } = true;
        
        public bool EnableIssuanceService { get; set; } = true;

        public int ValidationCheckInterval { get; set; } = 60;

        public int IssuanceCheckInterval { get; set; } = 60;
    }
}
