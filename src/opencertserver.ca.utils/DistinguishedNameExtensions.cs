namespace OpenCertServer.Ca.Utils
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    public static class DistinguishedNameExtensions
    {
        public static string? GetPart(this X500DistinguishedName distinguishedName, string part)
        {
            var parts = GetParts(distinguishedName);
            var found = parts.TryGetValue(part, out var result);

            return found ? result : null;
        }

        public static Dictionary<string, string> GetParts(this X500DistinguishedName distinguishedName)
        {
            return distinguishedName.Format(true)
                .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Split('='))
                .ToDictionary(x => x[0], x => x[1]);
        }
    }
}