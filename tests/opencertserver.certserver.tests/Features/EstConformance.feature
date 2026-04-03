@est
@rfc7030
@rfc8951
@rfc9908
Feature: EST conformance
Unified EST conformance requirements from RFC 7030 as updated by RFC 8951 and RFC 9908.

    Background:
        Given a certificate server
        And an EST client

    Rule: Transport security and URI handling

        Scenario: RFC 7030 Section 3.2.2 requires the well-known EST path prefix and mandatory operation paths
            When the client requests the EST operation path "/cacerts"
            Then the EST server MUST accept requests below "/.well-known/est"
            And the EST server MUST support the "/cacerts" operation

        Scenario Outline: RFC 7030 Section 3.2.2 requires the mandatory EST enrollment operation paths
            When the client requests the EST operation path "<operation>"
            Then the EST server MUST accept requests below "/.well-known/est"
            And the EST server MUST support the "<operation>" operation

            Examples:
              | operation        |
              | /simpleenroll    |
              | /simplereenroll  |

        Scenario: RFC 7030 Section 3.2.2 allows an additional CA label without shadowing registered operation paths
            Given the EST server is configured with an additional CA label
            Then the CA label MUST NOT be equal to any EST operation path segment
            And the EST server MUST provide service both with and without the additional CA label

        Scenario: RFC 7030 Sections 3.3 and 3.3.1 require HTTPS, TLS 1.1 or later, and certificate-based server authentication
            When an EST client connects to the EST server
            Then HTTPS MUST be used for EST communication
            And TLS 1.1 or a later version MUST be used for EST communication
            And TLS server authentication with certificates MUST be supported
            And the EST server certificate MUST conform to RFC 5280
            And TLS session resumption SHOULD be supported

        Scenario: RFC 7030 Sections 3.2.3 and 3.3.2 require protected HTTP authentication and certificate-based client authentication support
            When the EST server challenges the client for HTTP authentication
            Then HTTP Basic and Digest authentication MUST only be performed over TLS 1.1 or later
            And NULL cipher suites MUST NOT be used
            And anonymous cipher suites MUST NOT be used
            And the EST server MUST support certificate-based client authentication
            And the EST server MUST perform client authorization checks

        Scenario: RFC 7030 Sections 3.3.3 and 6 restrict certificate-less mutual authentication and deprecated TLS cipher suites
            When the EST server accepts certificate-less TLS mutual authentication for enrollment
            Then the negotiated cipher suite MUST resist dictionary attacks
            And the negotiated cipher suite MUST be based on a zero-knowledge protocol
            And TLS cipher suites containing "_EXPORT_" MUST NOT be used
            And TLS cipher suites containing "_DES_" MUST NOT be used

        Scenario: RFC 7030 Section 3.5 requires verification of tls-unique POP linkage whenever it is supplied
            When the client submits tls-unique channel-binding information in the certification request
            Then the EST server MUST verify the tls-unique value
            And if the request is rejected with a Full PKI Response the CMCFailInfo MUST be "popFailed"
            And if a human-readable reject message is returned it SHOULD explain that linking identity and proof-of-possession is required

        Scenario: RFC 7030 Section 3.2.1 defines redirect handling for EST operations
            When the EST server returns an HTTP redirect for an EST request
            Then the client SHOULD follow same-origin redirects without user input after enforcing the initial security checks
            And the client MUST establish a new TLS connection and repeat all security checks for a redirected origin
            And non-GET or non-HEAD redirects to another origin MUST require user input

    Rule: Trust anchor configuration, authorization, and bootstrap behavior

        Scenario: RFC 7030 Section 3.1 requires explicit trust anchor configuration and the ability to disable implicit trust anchors
            When the EST client is configured for EST server authentication
            Then the implementation MUST provide a way to designate Explicit trust anchors
            And the implementation MUST provide a way to disable any Implicit trust anchor database

        Scenario: RFC 7030 Section 3.6 requires the client to authorize the EST server before continuing the protocol
            When the EST client receives a response from the EST server
            Then the client MUST check EST server authorization before accepting the response
            And the client MUST check EST server authorization before responding to an HTTP authentication challenge

        Scenario: RFC 7030 Sections 3.6.1 and 3.6.2 define authorization checks for Explicit and Implicit trust anchors
            When the EST server certificate is validated using an Explicit trust anchor database entry
            Then the client MUST authorize either the configured URI or the most recent HTTP redirection URI according to RFC 6125
            And the EST server certificate MAY instead contain the id-kp-cmcRA extended key usage extension
            When the EST server certificate is validated using an Implicit trust anchor database entry
            Then the client MUST authorize the configured URI and every HTTP redirection URI according to RFC 6125

        Scenario: RFC 7030 Section 4.1.1 defines bootstrap distribution of CA certificates for minimally configured clients
            Given the EST client has neither an Explicit nor an Implicit trust anchor database for the EST server
            When the client performs bootstrap CA certificate distribution
            Then the client MAY provisionally complete TLS only to access "/cacerts" or "/fullcmc"
            And the client MUST NOT answer HTTP authentication challenges on the unauthenticated connection
            And the client MUST extract the trust anchor information from the response and engage a human user for out-of-band authorization
            And the client MUST NOT perform any other EST protocol exchange until the trust anchor response has been accepted and a new TLS session has been established with certificate-based server authentication

    Rule: RFC 8951 base64 processing updates apply uniformly to EST payloads

        Scenario Outline: RFC 8951 requires EST endpoints to ignore Content-Transfer-Encoding header values
            When the EST endpoint "<operation>" receives a base64-encoded DER body with any Content-Transfer-Encoding header
            Then the EST endpoint MUST ignore the Content-Transfer-Encoding header value
            And the EST endpoint MUST process the body as RFC 4648 base64-encoded DER

            Examples:
              | operation       |
              | /simpleenroll   |
              | /simplereenroll |
              | /fullcmc        |
              | /serverkeygen   |
              | /csrattrs       |

        Scenario Outline: RFC 8951 requires receivers to tolerate whitespace in base64 EST payloads
            When the EST endpoint "<operation>" receives a base64 body containing spaces tabs carriage returns or line feeds
            Then the EST receiver SHOULD tolerate the whitespace while decoding the body

            Examples:
              | operation       |
              | /cacerts        |
              | /fullcmc        |
              | /serverkeygen   |
              | /csrattrs       |

    Rule: Distribution of CA certificates using /cacerts

        Scenario: RFC 7030 Sections 4.1.2 and 4.1.3 define the /cacerts exchange
            When the EST client requests "/.well-known/est/cacerts"
            Then the EST server SHOULD NOT require client authentication or authorization
            And a successful response MUST use HTTP status code 200
            And a successful response MUST use the content type "application/pkcs7-mime"
            And a successful response MUST be a certs-only CMC Simple PKI Response
            And the response body MUST be RFC 4648 base64-encoded DER as updated by RFC 8951

        Scenario: RFC 7030 Section 4.1.3 requires the current EST trust anchor chain in the /cacerts response
            When the EST server returns CA certificates
            Then the current root CA certificate MUST be included in the response
            And every additional certificate needed to build a chain from an EST CA-issued certificate to the current EST CA trust anchor MUST be included in the response

        Scenario: RFC 7030 Section 4.1.3 recommends root CA key update certificates in the /cacerts response
            When the EST server supports root CA key rollover
            Then the /cacerts response SHOULD include the OldWithOld certificate
            And the /cacerts response SHOULD include the OldWithNew certificate
            And the /cacerts response SHOULD include the NewWithOld certificate

        Scenario: Rolling over the active EST CA updates both the issuing chain and the published rollover bundle
            Given the EST server remembers its current CA certificate
            When the active EST CA profile is rolled over to a new key and certificate
            And the EST server returns CA certificates
            Then the current root CA certificate MUST be different from the pre-rollover root
            And the current root CA certificate MUST be included in the response
            And the /cacerts response SHOULD include the OldWithOld certificate
            And the /cacerts response SHOULD include the OldWithNew certificate
            And the /cacerts response SHOULD include the NewWithOld certificate
            When I enroll with a valid JWT
            Then newly issued certificates MUST chain to the current root CA certificate

    Rule: Simple enrollment using /simpleenroll

        Scenario: RFC 7030 Sections 4.2 and 4.2.1 allow authenticated simple enrollment to issue a certificate
            When I enroll with a valid JWT
            Then I should get a certificate

        Scenario: RFC 7030 Sections 4.2 and 4.2.1 require authenticated and authorized simple enrollment requests
            When the client POSTs a PKCS #10 certification request to "/.well-known/est/simpleenroll"
            Then the EST server MUST authenticate the client
            And the EST server MUST verify the client's authorization
            And if the client submitted tls-unique POP information the EST server MUST verify it

        Scenario: RFC 7030 Section 4.2.1 defines the simple enrollment request format
            When the client POSTs to "/.well-known/est/simpleenroll"
            Then the request body MUST be a Simple PKI Request containing a PKCS #10 certification request
            And the request content type MUST be "application/pkcs10"

        Scenario: RFC 7030 Section 4.2.1 constrains proof-of-possession signing for simple enrollment requests
            When the CSR KeyUsage extension allows digital signatures
            Then the client MUST generate the CSR signature using the private key being certified
            When the CSR KeyUsage extension prohibits digital signatures but the private key can create signatures
            Then the client MAY still sign the CSR with that private key
            And the private key MUST NOT be used for any other signature operations

        Scenario: RFC 7030 Section 4.2.3 defines the successful simple enrollment response
            When the EST server successfully processes a simple enrollment request
            Then the response MUST use HTTP status code 200
            And the response content type MUST be "application/pkcs7-mime"
            And the response MUST be a certs-only CMC Simple PKI Response
            And the response MUST contain only the issued certificate

        Scenario: RFC 7030 Section 4.2.3 and RFC 8951 define simple enrollment error handling
            When the EST server rejects a simple enrollment request
            Then the response MUST use an HTTP 4xx or 5xx status code
            And the response MAY include an "application/pkcs7-mime" error body
            And if the content type is not set the response body MUST be a plaintext human-readable error message
            And the server MAY use the "text/plain" content type for the human-readable error

        Scenario: RFC 7030 Section 4.2 allows manual authorization with a Retry-After response
            When the EST server accepts a simple enrollment request for manual authorization
            Then the response MUST use HTTP status code 202
            And the response MUST include a Retry-After header
            And the server MAY include informative human-readable content
            And the server MUST retain the state needed to recognize later retries of the same request

    Rule: Simple re-enrollment using /simplereenroll

        Scenario: RFC 7030 Sections 2.3 and 4.2.2 allow authenticated re-enrollment to issue a renewed certificate
            When I enroll with a valid JWT
            And I get a certificate
            And I use the certificate to re-enroll without a valid JWT
            Then I should get a new certificate

        Scenario: RFC 7030 Sections 4.2 and 4.2.2 require authenticated and authorized re-enrollment requests
            When the client POSTs a certification request to "/.well-known/est/simplereenroll"
            Then the EST server MUST authenticate the client
            And the EST server MUST verify the client's authorization
            And if the client submitted tls-unique POP information the EST server MUST verify it

        Scenario: RFC 7030 Section 4.2.2 constrains the simple re-enrollment request identity fields
            When the client POSTs to "/.well-known/est/simplereenroll"
            Then the certification request Subject field MUST be identical to the current certificate Subject field
            And the certification request SubjectAltName extension MUST be identical to the current certificate SubjectAltName extension
            And the client MAY include the ChangeSubjectName attribute to request different values in the new certificate

        Scenario: RFC 7030 Section 4.2.2 distinguishes certificate renewal from certificate rekeying
            When the client submits the same SubjectPublicKeyInfo as the current certificate
            Then the EST server MUST treat the request as certificate renewal
            When the client submits a different SubjectPublicKeyInfo than the current certificate
            Then the EST server MUST treat the request as certificate rekeying

        Scenario: RFC 7030 Section 4.2.3 and RFC 8951 define simple re-enrollment error handling
            When the EST server rejects a simple re-enrollment request
            Then the response MUST use an HTTP 4xx or 5xx status code
            And the response MAY include an "application/pkcs7-mime" error body
            And if the content type is not set the response body MUST be a plaintext human-readable error message
            And the server MAY use the "text/plain" content type for the human-readable error

    Rule: Optional Full CMC support using /fullcmc

        Scenario: RFC 7030 Section 4.3 makes /fullcmc optional but specifies request validation when implemented
            Given the EST server implements "/fullcmc"
            When the client POSTs an invalid Full PKI Request to "/.well-known/est/fullcmc"
            Then the EST server MUST reject the message
            And the request content type MUST be "application/pkcs7-mime" with the smime-type parameter "CMC-request"
            And the request body MUST be RFC 4648 base64-encoded DER as updated by RFC 8951

        Scenario: RFC 7030 Section 4.3.2 defines successful Full CMC responses when /fullcmc is implemented
            Given the EST server implements "/fullcmc"
            When the EST server successfully processes a Full CMC request
            Then the response MUST use HTTP status code 200
            And the response content type MUST be "application/pkcs7-mime"
            And the response MUST contain either a certs-only Simple PKI Response or a Full PKI Response with smime-type "CMC-response"
            And the response body MUST be RFC 4648 base64-encoded DER as updated by RFC 8951

        Scenario: RFC 7030 Section 4.3.2 defines Full CMC error responses when /fullcmc is implemented
            Given the EST server implements "/fullcmc"
            When the EST server rejects a Full CMC request
            Then the response MUST use an HTTP 4xx or 5xx status code
            And the response MUST include a CMC error body with the content type "application/pkcs7-mime"

    Rule: Optional server-side key generation using /serverkeygen

        Scenario: RFC 7030 Section 4.4 requires authenticated, authorized, and confidential server-side key generation when implemented
            Given the EST server implements "/serverkeygen"
            When the client POSTs a server-side key generation request
            Then the EST server MUST authenticate the client
            And the EST server MUST authorize the client
            And cipher suites with NULL confidentiality MUST NOT be used
            And the TLS cipher suite used to return the private key and certificate MUST offer confidentiality commensurate with the private key being delivered

        Scenario: RFC 7030 Section 4.4.1 reuses the enroll CSR format but requires the server to ignore the CSR public key and signature
            Given the EST server implements "/serverkeygen"
            When the client POSTs a server-side key generation request
            Then the request format MUST match the /simpleenroll CSR format
            And the EST server SHOULD treat the CSR as it would any enroll or re-enroll CSR
            And the EST server MUST ignore the CSR public key values
            And the EST server MUST ignore the CSR signature

        Scenario: RFC 7030 Section 4.4.1 requires key-delivery metadata when additional encryption is requested
            Given the EST server implements "/serverkeygen"
            When the client requests private key encryption beyond the TLS transport
            Then the client MUST include a CSR attribute identifying the encryption key to use
            And the client MUST include an SMIMECapabilities attribute identifying acceptable key encipherment algorithms

        Scenario Outline: RFC 7030 Sections 4.4.1.1 and 4.4.1.2 require errors when the requested key-encryption material is unavailable
            Given the EST server implements "/serverkeygen"
            When the client requests <protection> protection for the returned private key and the indicated protection key is unavailable or unusable
            Then the EST server MUST terminate the request with an error

            Examples:
              | protection  |
              | symmetric   |
              | asymmetric  |

        Scenario: RFC 7030 Section 4.4.2 defines the successful server-side key generation response
            Given the EST server implements "/serverkeygen"
            When the EST server successfully processes a server-side key generation request
            Then the response MUST use HTTP status code 200
            And the response content type MUST be "multipart/mixed"
            And the response MUST contain one private key part and one certificate part

        Scenario: RFC 7030 Section 4.4.2 and RFC 8951 define the unencrypted private key response part
            Given the EST server implements "/serverkeygen"
            When the EST server returns a server-generated private key without additional application-layer encryption
            Then the private key part MUST use the content type "application/pkcs8"
            And the private key part MUST be RFC 4648 base64-encoded DER PrivateKeyInfo

        Scenario: RFC 7030 Section 4.4.2 and RFC 8951 define the encrypted private key response part
            Given the EST server implements "/serverkeygen"
            When the EST server returns a server-generated private key with additional application-layer encryption
            Then the private key part MUST use the content type "application/pkcs7-mime"
            And the private key part MUST include the smime-type parameter "server-generated-key"
            And the private key part MUST be RFC 4648 base64-encoded DER CMS EnvelopedData

        Scenario: RFC 7030 Section 4.4.2 requires the certificate part to match simple enrollment semantics
            Given the EST server implements "/serverkeygen"
            When the EST server returns the certificate part of a server-side key generation response
            Then the certificate part MUST exactly match the certificate response used for "/simpleenroll"

        Scenario: RFC 7030 Section 4.4.2 and RFC 8951 define server-side key generation error handling
            Given the EST server implements "/serverkeygen"
            When the EST server rejects a server-side key generation request
            Then the response MUST use an HTTP 4xx or 5xx status code
            And if the content type is not set the response body MUST be a plaintext human-readable error message
            And the server MAY use the "text/plain" content type for the human-readable error

    Rule: CSR attributes using /csrattrs

        Scenario: RFC 7030 Sections 4.5 and 4.5.1 define the /csrattrs request and its authentication expectations
            When the EST client requests "/.well-known/est/csrattrs"
            Then the EST server SHOULD NOT require client authentication or authorization to reply

        Scenario: RFC 7030 Section 4.5.2 defines the status codes for CSR attributes availability
            When locally configured policy provides CSR attributes for the authenticated EST client
            Then the response MUST use HTTP status code 200
            When CSR attributes are unavailable
            Then the response MAY use HTTP status code 204 or HTTP status code 404
            And the EST server MAY still reject a later enrollment request for incomplete CSR attributes

        Scenario: RFC 7030 Section 4.5.2 and RFC 8951 define the CSR attributes response encoding
            When the EST server returns CSR attributes
            Then the response content type MUST be "application/csrattrs"
            And the response body MUST be RFC 4648 base64-encoded DER
            And the response body MUST encode a CsrAttrs SEQUENCE

        Scenario: RFC 7030 Section 4.5.2 requires unrecognized CSR attributes to be ignored by clients
            When the CSR attributes response contains an unrecognized OID or attribute
            Then the client MUST ignore the unrecognized OID or attribute

        Scenario: RFC 7030 Section 4.5.2 defines empty CSR attributes semantics
            When the EST server has no specific additional CSR information to request
            Then the EST server MAY return an empty CsrAttrs SEQUENCE
            And the empty CsrAttrs SEQUENCE MUST be treated as equivalent to HTTP 204 or HTTP 404

        Scenario: RFC 7030 Section 4.5.2 requires algorithm and POP requirements to be signaled explicitly
            When the CA requires a particular cryptographic algorithm or signature scheme
            Then the EST server MUST provide that requirement in the CSR attributes response
            When the EST server requires linking identity and proof-of-possession
            Then the CSR attributes response MUST include the challengePassword OID

        Scenario: RFC 7030 Section 4.5.2 recommends structural alignment between CSR attributes and the requested CSR
            When the EST server encodes CSR attributes
            Then the structure of the CSR attributes response SHOULD reflect the structure of the CSR being requested

        Scenario: RFC 9908 Section 3.2 constrains legacy extension requirements in the unstructured CSR attributes response
            When the EST server encodes extension requirements using the original RFC 7030 CSR attributes format
            Then the attribute type MUST be id-ExtensionReq
            And there MUST be only one id-ExtensionReq attribute
            And the id-ExtensionReq values field MUST contain exactly one element of type Extensions
            And the Extensions value MUST NOT contain multiple Extension elements with the same extnID

        Scenario: RFC 9908 Section 3.2 constrains public key requirements in the unstructured CSR attributes response
            When the EST server requires a public key of a specific type using the original RFC 7030 CSR attributes format
            Then the response MUST include exactly one attribute whose type identifies the required key type
            And the values field MAY be empty if no further key requirements are imposed
            And otherwise the values field MUST contain suitable parameters for the chosen key type

        Scenario: RFC 9908 Section 3.4 allows coexistence of legacy and template-based CSR attribute styles
            When the EST server needs to interoperate with legacy and updated clients
            Then the EST server MAY include the legacy unstructured CSR attributes elements
            And the EST server MAY also include the CertificationRequestInfoTemplate elements for updated clients

        Scenario: RFC 9908 Section 4 requires updated clients to prefer the template-based CSR attributes form when both are present
            When the CSR attributes response contains both legacy and template-based CSR attribute encodings
            Then a client that understands both encodings MUST use only the template-based form
            And the client MUST ignore the other CsrAttrs elements

        Scenario: RFC 9908 Section 3.4 constrains the CertificationRequestInfoTemplate subject fields
            When the EST server returns a CertificationRequestInfoTemplate
            Then the version field MUST be v1
            And the subject field MUST be present if the server places requirements on the subject RDNs
            And the subject field MUST be absent if the server places no subject RDN requirements
            And each required RDN type MUST be present in the subject field
            And each RDN type that is not required MUST be absent from the subject field

        Scenario: RFC 9908 Section 3.4 constrains the CertificationRequestInfoTemplate key fields
            When the EST server returns a CertificationRequestInfoTemplate
            Then the subjectPKInfo field MUST be absent if the server places no key requirements
            And the subjectPKInfo field MUST be present if the server places key requirements
            And when RSA key size requirements are specified the subjectPublicKey field MUST be present with a placeholder modulus of the desired length
            And otherwise the subjectPublicKey field MUST be absent

        Scenario: RFC 9908 Section 3.4 constrains template-based extension requirements
            When the EST server returns a CertificationRequestInfoTemplate
            Then full X.509 extension requirements MUST use id-ExtensionReq
            And partial X.509 extension requirements MAY use id-aa-extensionReqTemplate
            And the attributes field MUST NOT contain multiple id-aa-extensionReqTemplate attributes
            And the attributes field MUST NOT contain both id-ExtensionReq and id-aa-extensionReqTemplate
            And each id-aa-extensionReqTemplate values field MUST contain exactly one element of type ExtensionTemplate

