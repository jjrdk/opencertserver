﻿namespace OpenCertServer.Acme.Server.Configuration
{
    public class TOSOptions
    {
        public bool RequireAgreement { get; set; }
        public string? Url { get; set; }

        public DateTime? LastUpdate { get; set; }
    }
}
