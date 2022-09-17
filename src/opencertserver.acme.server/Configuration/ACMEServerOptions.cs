namespace OpenCertServer.Acme.Server.Configuration
{
    public sealed class AcmeServerOptions
    {
        public BackgroundServiceOptions HostedWorkers { get; set; } = new();

        public string? WebsiteUrl { get; set; }

        public TOSOptions TOS { get; set; } = new();
    }
}
