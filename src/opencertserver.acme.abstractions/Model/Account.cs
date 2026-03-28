using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using System.Collections.Generic;
using System.Linq;

    /// <summary>
    /// Represents an ACME account, including its key, contacts, status, and terms of service agreement.
    /// </summary>
    public sealed class Account : IVersioned
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Account"/> class with the specified key, contacts, and terms of service acceptance.
        /// </summary>
        /// <param name="jwk">The JSON Web Key for the account.</param>
        /// <param name="contacts">The contact URIs for the account.</param>
        /// <param name="tosAccepted">The date/time the terms of service were accepted, or null if not accepted.</param>
        public Account(JsonWebKey jwk, IEnumerable<string>? contacts, DateTimeOffset? tosAccepted)
        {
            AccountId = GuidString.NewValue();

            Jwk = jwk;
            Contacts = contacts?.ToList();
            TosAccepted = tosAccepted;
        }

        /// <summary>
        /// Gets the unique account identifier.
        /// </summary>
        public string AccountId { get; }

        /// <summary>
        /// Gets or sets the account status (e.g., valid, deactivated, revoked).
        /// </summary>
        public AccountStatus Status { get; set; }

        /// <summary>
        /// Gets the JSON Web Key associated with the account.
        /// </summary>
        public JsonWebKey Jwk { get; }

        /// <summary>
        /// Gets the list of contact URIs for the account.
        /// </summary>
        public List<string>? Contacts { get; private set; }

        /// <summary>
        /// Gets the date/time the terms of service were accepted, or null if not accepted.
        /// </summary>
        public DateTimeOffset? TosAccepted { get; private set; }

        /// <summary>
        /// Gets or sets the concurrency token for optimistic concurrency control.
        /// </summary>
        public long Version { get; set; }
    }
