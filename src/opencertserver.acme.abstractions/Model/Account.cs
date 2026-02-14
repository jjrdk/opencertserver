using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using System.Collections.Generic;
using System.Linq;

 public sealed class Account : IVersioned
{
    public Account(JsonWebKey jwk, IEnumerable<string>? contacts, DateTimeOffset? tosAccepted)
    {
        AccountId = GuidString.NewValue();

        Jwk = jwk;
        Contacts = contacts?.ToList();
        TosAccepted = tosAccepted;
    }

    public string AccountId { get; }
    public AccountStatus Status { get; private set; }

    public JsonWebKey Jwk { get; }

    public List<string>? Contacts { get; private set; }
    public DateTimeOffset? TosAccepted { get; private set; }

    /// <summary>
    /// Concurrency Token
    /// </summary>
    public long Version { get; set; }
}
