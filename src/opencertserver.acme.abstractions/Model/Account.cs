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
        public Account(JsonWebKey jwk, IEnumerable<string>? contacts, DateTimeOffset? tosAccepted, string? externalAccountId = null)
        {
            AccountId = GuidString.NewValue();

            Jwk = jwk;
            Contacts = contacts?.ToList();
            TosAccepted = tosAccepted;
            ExternalAccountId = externalAccountId;
        }

        /// <summary>
        /// Gets the external account key identifier bound to this account during creation,
        /// or null if the account was not created with an external account binding.
        /// </summary>
        public string? ExternalAccountId { get; }

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
        public JsonWebKey Jwk { get; private set; }

        /// <summary>
        /// Gets the list of contact URIs for the account.
        /// </summary>
        public List<string>? Contacts { get; private set; }

        /// <summary>
        /// Gets the date/time the terms of service were accepted, or null if not accepted.
        /// </summary>
        public DateTimeOffset? TosAccepted { get; private set; }

            /// <summary>
            /// Replaces the account contact URIs.
            /// </summary>
            /// <param name="contacts">The new contact URIs, or null to clear them.</param>
            public void UpdateContacts(IEnumerable<string>? contacts)
            {
                Contacts = contacts?.ToList();
            }

            /// <summary>
            /// Records acceptance of the current terms of service.
            /// </summary>
            public void AgreeToTermsOfService()
            {
                TosAccepted ??= DateTimeOffset.UtcNow;
            }

            /// <summary>
            /// Deactivates the account.
            /// </summary>
            public void Deactivate()
            {
                Status = AccountStatus.Deactivated;
            }

        /// <summary>
        /// Replaces the account key.
        /// </summary>
        /// <param name="jwk">The replacement JSON Web Key.</param>
        public void ReplaceKey(JsonWebKey jwk)
        {
            Jwk = jwk ?? throw new ArgumentNullException(nameof(jwk));
        }

        /// <summary>
        /// Gets or sets the concurrency token for optimistic concurrency control.
        /// </summary>
        public long Version { get; set; }
    }
