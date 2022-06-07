namespace OpenCertServer.Acme.Server.Configuration
{
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.IO;

    public class FileStoreOptions : IValidatableObject
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

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (string.IsNullOrWhiteSpace(BasePath) || !Directory.Exists(BasePath))
            {
                yield return new ValidationResult($"FileStore BasePath ({BasePath}) was empty or did not exist.", new[] { nameof(BasePath) });
            }
        }
    }
}
