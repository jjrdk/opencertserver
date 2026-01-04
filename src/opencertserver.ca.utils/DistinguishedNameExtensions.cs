namespace OpenCertServer.Ca.Utils;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

public static class DistinguishedNameExtensions
{
    extension(X500DistinguishedName distinguishedName)
    {
        public string? GetPart(string part)
        {
            var parts = GetParts(distinguishedName);
            var found = parts.TryGetValue(part, out var result);

            return found ? result : null;
        }

        public Dictionary<string, string> GetParts()
        {
            return distinguishedName.Format(true)
                .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Split('='))
                .ToDictionary(x => x[0], x => x[1]);
        }
    }
}