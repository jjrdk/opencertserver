namespace OpenCertServer.Acme.Server.Configuration;

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;

public sealed class FileStoreOptions
{
    public string BasePath { get; set; } = "./";

    public string NoncePath
    {
        get { return Path.Combine(BasePath, "Nonces"); }
    }

    public string AccountPath
    {
        get { return Path.Combine(BasePath, "Accounts"); }
    }

    public string OrderPath
    {
        get { return Path.Combine(BasePath, "Orders"); }
    }

    public string WorkingPath
    {
        get { return Path.Combine(BasePath, "_work"); }
    }
}
