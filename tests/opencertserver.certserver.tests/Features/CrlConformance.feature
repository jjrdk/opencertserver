@crl
@rfc5280
Feature: CRL conformance
CRL conformance requirements from RFC 5280 Section 5.
The scenarios below inventory the CRL issuer behavior that the OpenCertServer CRL implementation must satisfy.
They are intentionally written before adding step implementations so they can drive the CRL work in TDD style.

    Background:
        Given a certificate server

    Rule: CRL outer structure and signature (RFC 5280 §5.1.1)

        Scenario: RFC 5280 §5.1.1 requires a CertificateList to be a DER SEQUENCE of tbsCertList signatureAlgorithm and signatureValue
            When the CA generates a CRL
            Then the CRL MUST be a DER-encoded SEQUENCE
            And the CRL MUST contain a TBSCertList field
            And the CRL MUST contain a signatureAlgorithm AlgorithmIdentifier field
            And the CRL MUST contain a signatureValue BIT STRING field
            And the signatureValue BIT STRING MUST have zero unused bits

        Scenario: RFC 5280 §5.1.1.2 requires the outer signatureAlgorithm to be identical to the signature field inside TBSCertList
            When the CA generates a CRL
            Then the signatureAlgorithm algorithm OID in the outer CertificateList MUST equal the signature algorithm OID in the TBSCertList
            And the signatureAlgorithm parameters in the outer CertificateList MUST equal the signature parameters in the TBSCertList

        Scenario: RFC 5280 §5.1.1.3 requires the CRL signature to be verifiable with the issuing CA public key
            When the CA generates a CRL
            Then the CRL signatureValue MUST be a valid cryptographic signature over the DER encoding of the TBSCertList
            And the signature MUST be verifiable using the public key in the CA certificate identified by the issuer field

    Rule: TBSCertList mandatory and optional fields (RFC 5280 §5.1.2)

        Scenario: RFC 5280 §5.1.2.1 requires version v2 when CRL extensions are present
            When the CA generates a CRL containing one or more CRL extensions
            Then the TBSCertList version field MUST be present
            And the version field value MUST encode v2 (integer value 1)

        Scenario: RFC 5280 §5.1.2.1 allows the version field to be absent for v1 CRLs with no extensions
            When the CA generates a CRL containing no CRL extensions
            Then the TBSCertList version field MAY be absent indicating v1 by default

        Scenario: RFC 5280 §5.1.2.3 requires the issuer field to be a non-empty distinguished name
            When the CA generates a CRL
            Then the TBSCertList issuer field MUST be present
            And the issuer distinguished name MUST be non-empty
            And the issuer distinguished name MUST match the subject name of the signing CA certificate

        Scenario: RFC 5280 §5.1.2.4 requires thisUpdate to be present and correctly encoded
            When the CA generates a CRL
            Then the TBSCertList MUST include a thisUpdate time value
            And thisUpdate MUST be encoded as UTCTime when the date is before year 2050
            And thisUpdate MUST be encoded as GeneralizedTime when the date is year 2050 or later

        Scenario: RFC 5280 §5.1.2.5 recommends nextUpdate be present and correctly encoded
            When the CA generates a CRL
            Then the TBSCertList SHOULD include a nextUpdate time value
            And if nextUpdate is present it MUST be encoded as UTCTime when the date is before year 2050
            And if nextUpdate is present it MUST be encoded as GeneralizedTime when the date is year 2050 or later
            And if nextUpdate is present it MUST be later than thisUpdate

        Scenario: RFC 5280 §5.1.2.6 requires the revokedCertificates field to be absent when no certificates have been revoked
            When the CA generates a CRL and no certificates have been revoked
            Then the TBSCertList revokedCertificates field MUST be absent from the encoding

        Scenario: RFC 5280 §5.1.2.6 requires each revoked certificate entry to contain a serial number and a revocation time
            When the CA generates a CRL for a revoked certificate
            Then each revoked certificate entry MUST contain a userCertificate serial number
            And each revoked certificate entry MUST contain a revocationDate time value
            And the userCertificate serial number MUST match the serial number of the revoked certificate

        Scenario: RFC 5280 §5.1.2.6 requires revocationDate to use UTCTime for dates before year 2050
            When a certificate is revoked with a revocation date before year 2050
            Then the revocationDate in the CRL entry MUST be encoded as UTCTime

        Scenario: RFC 5280 §5.1.2.6 requires revocationDate to use GeneralizedTime for dates from year 2050 onward
            When a certificate is revoked with a revocation date in year 2050 or later
            Then the revocationDate in the CRL entry MUST be encoded as GeneralizedTime

    Rule: Standard CRL extensions (RFC 5280 §5.2)

        Scenario: RFC 5280 §5.2 requires CRL extensions to appear only in v2 CRLs
            When a CRL contains one or more CRL extensions
            Then the CRL version MUST be v2

        Scenario: RFC 5280 §5.2.1 requires authorityKeyIdentifier to be present and non-critical in all CRLs from conforming CAs
            When the CA generates a CRL
            Then the CRL MUST include an authorityKeyIdentifier extension
            And the authorityKeyIdentifier extension MUST NOT be marked critical

        Scenario: RFC 5280 §5.2.1 requires the authorityKeyIdentifier to identify the signing CA key
            When the CA generates a CRL
            Then the authorityKeyIdentifier keyIdentifier value MUST match the subjectKeyIdentifier of the signing CA certificate

        Scenario: RFC 5280 §5.2.2 allows an issuerAltName extension with the same semantics as the certificate issuerAltName
            When the signing CA certificate contains an issuer alternative name
            Then the CRL MAY include an issuerAltName extension
            And if the issuerAltName extension is present it MUST NOT be marked critical

        Scenario: RFC 5280 §5.2.3 requires cRLNumber to be present and non-critical in all CRLs
            When the CA generates a CRL
            Then the CRL MUST include a cRLNumber extension
            And the cRLNumber extension MUST NOT be marked critical
            And the cRLNumber value MUST be a non-negative integer not exceeding 2 to the power of 159 minus 1

        Scenario: RFC 5280 §5.2.3 requires the CRL number to be monotonically increasing for the same issuer and scope
            When the CA generates two successive CRLs for the same issuer
            Then the cRLNumber of the second CRL MUST be strictly greater than the cRLNumber of the first CRL

        Scenario: RFC 5280 §5.2.4 requires the deltaCRLIndicator extension to be marked critical
            When a delta CRL is generated containing a deltaCRLIndicator extension
            Then the deltaCRLIndicator extension MUST be marked critical
            And the deltaCRLIndicator value MUST be the cRLNumber of the base CRL that the delta CRL supplements

        Scenario: RFC 5280 §5.2.5 requires the issuingDistributionPoint extension to be marked critical when present
            When a CRL contains an issuingDistributionPoint extension
            Then the issuingDistributionPoint extension MUST be marked critical

        Scenario: RFC 5280 §5.2.5 requires the onlyContainsUserCerts and onlyContainsCACerts fields to be mutually exclusive
            When a CRL contains an issuingDistributionPoint extension
            Then the onlyContainsUserCerts and onlyContainsCACerts fields MUST NOT both be TRUE

        Scenario: RFC 5280 §5.2.6 requires the freshestCRL extension to be non-critical when present
            When the CA generates a CRL containing a freshestCRL extension
            Then the freshestCRL extension MUST NOT be marked critical
            And the freshestCRL extension value MUST encode a valid CRLDistributionPoints sequence identifying the delta CRL locations

    Rule: CRL entry extensions (RFC 5280 §5.3)

        Scenario: RFC 5280 §5.3.1 allows a reasonCode extension on individual CRL entries
            When a certificate is revoked with a known reason
            Then the CRL entry SHOULD include a reasonCode extension
            And the reasonCode extension MUST NOT be marked critical
            And the reasonCode value MUST be one of the reason codes defined in RFC 5280

        Scenario: RFC 5280 §5.3.1 requires the reasonCode to not use unspecified when the actual reason is known
            When a certificate is revoked and the reason for revocation is known
            Then the CRL entry reasonCode SHOULD NOT be set to unspecified

        Scenario: RFC 5280 §5.3.1 restricts the removeFromCRL reason code to delta CRLs only
            When a CRL entry contains the removeFromCRL reason code
            Then the CRL containing that entry MUST be a delta CRL

        Scenario: RFC 5280 §5.3.2 allows an invalidityDate extension on individual CRL entries
            When a certificate is revoked and the actual date of compromise or invalidity is known
            Then the CRL entry MAY include an invalidityDate extension
            And the invalidityDate extension MUST NOT be marked critical
            And the invalidityDate value MUST be encoded as GeneralizedTime

        Scenario: RFC 5280 §5.3.2 allows invalidityDate to precede the revocationDate
            When the date of key compromise predates the formal revocation
            Then the invalidityDate MAY be earlier than the revocationDate in the same CRL entry

        Scenario: RFC 5280 §5.3.3 requires the certificateIssuer extension to be critical in indirect CRLs
            When a CRL is an indirect CRL containing entries for certificates not issued by the CRL signer
            Then each CRL entry for a certificate from a delegated issuer MUST include a certificateIssuer extension
            And the certificateIssuer extension MUST be marked critical
            And the first CRL entry for each issuer in the list MUST include the certificateIssuer extension
            And subsequent CRL entries for the same issuer MUST inherit the certificateIssuer value from the most recent entry that included it

    Rule: CRL distribution points in issued certificates (RFC 5280 §4.2.1.13)

        @with-crl-urls
        Scenario: RFC 5280 §4.2.1.13 requires issued certificates to include cRLDistributionPoints when the CA is configured with CRL URLs
            When the CA is configured with one or more CRL distribution point URIs
            Then certificates issued by the CA MUST include a cRLDistributionPoints extension
            And each distribution point MUST contain at least one URI

        @with-crl-urls
        Scenario: RFC 5280 §4.2.1.13 requires cRLDistributionPoints to be non-critical
            When the CA adds a cRLDistributionPoints extension to an issued certificate
            Then the cRLDistributionPoints extension MUST NOT be marked critical

        @with-crl-urls
        Scenario: RFC 5280 §4.2.1.13 requires URI form GeneralNames in the distributionPoint field
            When the CA encodes a distribution point URI in a certificate
            Then the distributionPoint name MUST use the uniformResourceIdentifier form of GeneralName

        Scenario: RFC 5280 §4.2.1.13 requires the scope of all distribution points to collectively cover all revocation reasons
            When a certificate contains a cRLDistributionPoints extension with a reasons field on any distribution point
            Then the union of reasons across all distribution points MUST cover all possible revocation reasons
            And a distribution point without a reasons field implicitly covers all reasons

        Scenario: RFC 5280 §4.2.1.13 requires the cRLIssuer field to identify the entity signing the CRL when it differs from the certificate issuer
            When a CRL distribution point is managed by an entity different from the certificate issuer
            Then the distributionPoint entry MUST include a cRLIssuer GeneralNames value identifying the CRL signer

    Rule: Freshest CRL extension in issued certificates (RFC 5280 §4.2.1.15)

        Scenario: RFC 5280 §4.2.1.15 allows a freshestCRL extension in end-entity certificates pointing to delta CRL locations
            When the CA is configured with delta CRL distribution point URIs
            Then issued certificates MAY include a freshestCRL extension
            And the freshestCRL extension MUST NOT be marked critical
            And the freshestCRL value MUST encode a CRLDistributionPoints sequence with at least one URI

    Rule: CRL HTTP endpoint and delivery

        Scenario: The CA CRL endpoint returns a DER-encoded CertificateList with the correct MIME type
            When an HTTP GET request is made to the CRL endpoint
            Then the HTTP response status MUST be 200
            And the response Content-Type MUST be "application/pkix-crl"
            And the response body MUST be a valid DER-encoded CertificateList

        Scenario: The CA CRL endpoint serves a profile-specific CRL when a profile name is provided
            When an HTTP GET request is made to the CRL endpoint for a named CA profile
            Then the HTTP response status MUST be 200
            And the returned CRL MUST be signed by the CA certificate for the named profile

        Scenario: The CA CRL endpoint returns an anonymous CRL when no profile name is given
            When an HTTP GET request is made to the default CRL endpoint without a profile name
            Then the HTTP response status MUST be 200
            And the returned CRL MUST be signed by the default CA certificate

