@acme
@rfc8555
Feature: ACME conformance
Server-relevant ACME conformance requirements from RFC 8555.
The scenarios below inventory the protocol requirements that the OpenCertServer ACME implementation must satisfy.
They are intentionally written before adding step implementations so they can drive the conformance work in TDD style.

    Background:
        Given a certificate server

    Rule: HTTPS transport, directory discovery, and index links

        Scenario: RFC 8555 Sections 6.1 and 7.1.1 require HTTPS transport and a directory resource
            When an ACME client connects to the ACME server
            Then HTTPS MUST be used for ACME communication outside local in-memory test transports
            And the ACME server MUST authenticate with X.509 certificates
            And the ACME directory MUST be reachable with an unauthenticated GET request
            And the directory response MUST be a JSON object

        Scenario: RFC 8555 Section 7.1.1 requires the directory to advertise mandatory resources and metadata
            When the client fetches the ACME directory
            Then the directory MUST contain the "newNonce" URL
            And the directory MUST contain the "newAccount" URL
            And the directory MUST contain the "newOrder" URL
            And the advertised mandatory resource URLs MUST be absolute HTTPS URLs
            And if the server supports certificate revocation the directory MUST contain the "revokeCert" URL
            And if the server supports account key rollover the directory MUST contain the "keyChange" URL
            And if the server requires external account binding the "meta.externalAccountRequired" field MUST be true
            And if the server requires agreement to terms of service the "meta.termsOfService" field SHOULD be present

        Scenario: RFC 8555 Section 7.1.1 allows the legacy newAuthz field to be omitted
            When the client fetches the ACME directory
            Then the ACME server MAY omit the legacy "newAuthz" field

        Scenario: RFC 8555 Sections 6.5 and 7.1.1 require an index link on ACME resource responses
            When the client sends a request to an ACME resource other than the directory
            Then the response MUST include a Link header with relation "index"
            And the index link MUST identify the directory resource

    Rule: Replay nonces and anti-replay protection

        @acme-item1
        Scenario: RFC 8555 Section 7.2 defines the newNonce resource
            When the client requests a new nonce with HEAD
            Then the ACME server MUST return a Replay-Nonce header
            And the newNonce response body MUST be empty
            And the newNonce response status code MUST indicate success
            When the client requests a new nonce with GET
            Then the ACME server SHOULD return a Replay-Nonce header

        @acme-item1
        Scenario: RFC 8555 Sections 6.4 and 6.5 require anti-replay protection on POST requests
            When the client sends a POST request to an ACME resource
            Then the JWS protected header MUST contain a nonce from the ACME server
            And the ACME server MUST reject a reused or otherwise unacceptable nonce
            And the rejection MUST use the "badNonce" ACME error type
            And the rejection response MUST include a fresh Replay-Nonce header

        @acme-item1
        Scenario: RFC 8555 Section 6.5 requires fresh nonces on successful POST responses
            When the client successfully POSTs to an ACME resource
            Then the response MUST include a fresh Replay-Nonce header

    Rule: JWS envelope validation and POST-as-GET behavior

        @acme-item3
        Scenario: RFC 8555 Sections 6.2 6.3 and 6.5 require ACME POST bodies to be signed JWS objects
            When the client POSTs to an ACME resource
            Then the request content type MUST be "application/jose+json"
            And the request body MUST be a flattened JWS JSON serialization
            And the JWS object MUST contain exactly one signature
            And the JWS protected header MUST contain the "alg" member
            And the JWS protected header MUST contain the "nonce" member
            And the JWS protected header MUST contain the "url" member
            And the JWS protected header MUST contain either "jwk" or "kid"
            And the JWS protected header MUST NOT contain both "jwk" and "kid"

        @acme-item3
        Scenario: RFC 8555 Section 6.2 requires ACME POST requests to use the application jose+json media type
            When the client POSTs an ACME request with the wrong content type
            Then the ACME server MUST reject the request

        @acme-item3
        Scenario: RFC 8555 Section 6.3 requires the protected header URL to match the request URL
            When the JWS protected header "url" value does not equal the actual request URL
            Then the ACME server MUST reject the request

        Scenario: RFC 8555 Section 6.2 requires POST-as-GET for ACME resource retrieval
            When the client fetches an ACME resource other than the directory or newNonce
            Then the client MUST use POST-as-GET
            And the JWS payload for the retrieval request MUST be the empty string
            And the ACME server MUST accept POST-as-GET for account order authorization challenge and certificate resources

        @acme-item3
        Scenario: RFC 8555 Section 6.2 forbids non-empty payloads on POST-as-GET requests
            When the client sends a POST-as-GET request with a non-empty payload
            Then the ACME server MUST reject the request

        @acme-item3
        Scenario: RFC 8555 Section 6.5 distinguishes account-creation requests from existing-account requests
            When the client POSTs to the newAccount resource
            Then the JWS protected header MUST contain a "jwk" member
            And the JWS protected header MUST NOT contain a "kid" member
            When the client POSTs to an existing account order authorization challenge finalize or certificate resource
            Then the JWS protected header MUST contain a "kid" member

        @acme-item3
        Scenario: RFC 8555 Section 6.5 requires newAccount requests to use a jwk rather than a kid
            When the client sends a newAccount request signed with a kid instead of a jwk
            Then the ACME server MUST reject the request

        @acme-item3
        Scenario: RFC 8555 Section 6.5 requires existing-account requests to use a kid rather than a jwk
            When the client sends an existing-account request signed with a jwk instead of a kid
            Then the ACME server MUST reject the request

        @acme-item3
        Scenario: RFC 8555 Section 6.5 requires unknown kids to be rejected as accountDoesNotExist
            When the client sends an existing-account request with an unknown kid
            Then the ACME server MUST reject the request with the "accountDoesNotExist" ACME error type

        @acme-item3
        Scenario: RFC 8555 Section 6.5 requires unsupported signature algorithms to be rejected
            When the client uses an unsupported JWS signature algorithm
            Then the ACME server MUST reject the request with the "badSignatureAlgorithm" ACME error type

    Rule: ACME problem documents and protocol errors

        @acme-item1
        Scenario: RFC 8555 Section 6.7 requires RFC 7807 style ACME problem documents
            When the ACME server rejects a request for a protocol reason
            Then the response content type MUST be "application/problem+json"
            And the body MUST contain the ACME problem "type"
            And the body MUST contain the human-readable "detail"
            And the body MUST contain the HTTP "status"
            And the problem type MUST be an "urn:ietf:params:acme:error:" URN

        Scenario: RFC 8555 Section 6.7 allows subproblems when multiple identifiers fail for different reasons
            When multiple identifiers in one request fail for different reasons
            Then the ACME server MAY return a top-level problem document containing "subproblems"
            And each subproblem SHOULD identify the affected identifier

        @acme-item1
        Scenario: RFC 8555 Section 6.5 requires protocol error responses to carry a fresh nonce
            When the ACME server returns an error response to a POST request
            Then the response MUST include a fresh Replay-Nonce header

    Rule: Account management

        @acme-item2
        Scenario: RFC 8555 Section 7.3 allows an ACME client to create a new account
            When an ACME client creates a new account
            Then the response MUST use status code 201
            And the response MUST include the account URL in the Location header
            And the response body MUST be an account object whose status is "valid"
            And the account object MUST include the orders URL

        @acme-item2
        Scenario: RFC 8555 Section 7.3 requires onlyReturnExisting to return an existing account without creating a new one
            When the client requests onlyReturnExisting for an existing account key
            Then the ACME server MUST return status code 200
            And the response body MUST describe the existing account
            When the client requests onlyReturnExisting for an unknown account key
            Then the ACME server MUST NOT create a new account
            And the ACME server MUST reject the request with the "accountDoesNotExist" ACME error type

        @acme-item2
        Scenario: RFC 8555 Section 7.3 requires account URLs to be dereferenceable with POST-as-GET
            When the client fetches an existing account by its account URL
            Then the ACME server MUST return the current account object

        @acme-item2
        Scenario: RFC 8555 Section 7.3.2 allows account updates
            When the client updates an existing account
            Then the ACME server MUST apply contact changes carried in the account object
            And the ACME server MUST record agreement to updated terms of service when requested
            And the response MUST return the updated account object

        @acme-item2
        Scenario: RFC 8555 Section 7.3.2 allows account deactivation
            When the client POSTs an account object with status "deactivated" to its account URL
            Then the ACME server MUST deactivate the account
            And the returned account object MUST have status "deactivated"

        Scenario: RFC 8555 Sections 7.1.1 and 7.3 conditionally require terms-of-service and external account binding enforcement
            Given the ACME server requires agreement to terms of service
            When the client creates a new account without agreeing to the terms of service
            Then the ACME server MUST reject the account creation request
            Given the ACME server requires external account binding
            When the client creates a new account without a valid external account binding
            Then the ACME server MUST reject the account creation request

    Rule: External Account Binding (RFC 8555 §7.3.4)

        @acme-eab
        Scenario: RFC 8555 Section 7.3.4 allows creating an account with a valid external account binding
            Given the ACME server has a provisioned external account key "test-eab-key-1"
            When the client creates a new account with a valid external account binding for key "test-eab-key-1"
            Then the response MUST use status code 201
            And the account MUST be linked to external account key "test-eab-key-1"

        @acme-eab
        Scenario: RFC 8555 Section 7.3.4 requires the EAB HMAC signature to be valid
            Given the ACME server requires external account binding
            And the ACME server has a provisioned external account key "test-eab-key-2"
            When the client creates a new account with an invalid EAB HMAC signature for key "test-eab-key-2"
            Then the ACME server MUST reject the account creation request

        @acme-eab
        Scenario: RFC 8555 Section 7.3.4 requires the EAB protected header url to match the newAccount URL
            Given the ACME server requires external account binding
            And the ACME server has a provisioned external account key "test-eab-key-3"
            When the client creates a new account with an EAB url mismatch for key "test-eab-key-3"
            Then the ACME server MUST reject the account creation request

        @acme-eab
        Scenario: RFC 8555 Section 7.3.4 requires the EAB payload to be the account JWK
            Given the ACME server requires external account binding
            And the ACME server has a provisioned external account key "test-eab-key-4"
            When the client creates a new account with an EAB payload that is not the account JWK for key "test-eab-key-4"
            Then the ACME server MUST reject the account creation request

        @acme-eab
        Scenario: RFC 8555 Section 7.3.4 prohibits reuse of an external account key
            Given the ACME server requires external account binding
            And the ACME server has a provisioned external account key "test-eab-key-5"
            When the client successfully creates a new account with external account key "test-eab-key-5"
            And the client attempts to create another account reusing external account key "test-eab-key-5"
            Then the ACME server MUST reject the account creation request

        @acme-eab
        Scenario: RFC 8555 Section 7.3.4 allows checking for an active external account key
            Given the ACME server has a provisioned external account key "test-eab-key-6"
            When the server checks whether external account key "test-eab-key-6" is active
            Then the external account key MUST be reported as active
            When the client successfully creates a new account with external account key "test-eab-key-6"
            And the server checks whether external account key "test-eab-key-6" is active
            Then the external account key MUST be reported as no longer active

    Rule: Orders and order objects

        @acme-item3
        Scenario Outline: RFC 8555 Section 7.4 allows the core certificate flow for supported account key algorithms
            Given an ACME client for <keyAlgorithm>
            When the client requests a certificate
            Then the client receives a certificate

            Examples:
              | keyAlgorithm |
              | RS256        |
              | ES256        |
              | ES384        |
              | ES512        |

        @acme-item4
        Scenario: RFC 8555 Section 7.4 requires new orders to create pending authorizations
            When the client creates a new order
            Then the response MUST use status code 201
            And the response MUST include the order URL in the Location header
            And the response body MUST be an order object
            And the order object MUST contain every requested identifier
            And the order object MUST contain one authorization URL per identifier
            And the order object MUST contain a finalize URL
            And the order object status MUST initially be "pending"

        @acme-item4
        Scenario: RFC 8555 Section 7.1.3 defines the order object fields and certificate link timing
            When the client fetches an order
            Then the order object MUST contain its status
            And the order object SHOULD contain an expires timestamp while it is pending ready or processing
            And the order object MUST reflect any accepted notBefore value
            And the order object MUST reflect any accepted notAfter value
            And the certificate URL MUST be absent until the order becomes "valid"
            And if the order becomes "invalid" the order object MUST include an error object

        @acme-item4
        Scenario: RFC 8555 Section 7.4 requires malformed new-order requests to be rejected
            When the client submits a new-order request without identifiers
            Then the ACME server MUST reject the request
            And the ACME server MUST reject the request with the "malformed" ACME error type

        Scenario: RFC 8555 Section 7.4 requires order URLs to be retrievable with POST-as-GET
            When the client fetches an existing order by its order URL
            Then the ACME server MUST return the current order object

        @acme-item2
        Scenario: RFC 8555 Section 7.3 requires the account orders list resource
            When the client fetches the account orders URL
            Then the ACME server MUST return the list of order URLs for that account
            And if the result is paginated the ACME server MUST use Link headers with relation "next"

        Scenario: RFC 8555 Sections 7.1.3 and 7.4 define wildcard authorization behavior
            When the client creates an order containing a wildcard DNS identifier
            Then the corresponding authorization object MUST set "wildcard" to true
            And the ACME server MUST require validation of the base domain name without the "*." prefix
            And the ACME server MUST NOT offer the "http-01" challenge for the wildcard identifier

    Rule: Authorization and challenge objects

        @acme-item5
        Scenario: RFC 8555 Section 7.1.4 defines the authorization object
            When the client fetches an authorization
            Then the authorization object MUST contain the identifier being authorized
            And the authorization object MUST contain the current status
            And pending authorizations SHOULD contain an expires timestamp
            And the authorization object MUST include its offered challenges

        @acme-item5
        Scenario: RFC 8555 Section 7.1.5 defines the challenge object
            When the client fetches a challenge
            Then the challenge object MUST contain its type
            And the challenge object MUST contain its URL
            And the challenge object MUST contain its status
            And the challenge object MUST contain its token
            And valid challenges SHOULD include the validation timestamp
            And invalid challenges SHOULD include an error object

        @acme-item5
        Scenario: RFC 8555 Section 7.5 requires challenge acknowledgements to trigger validation
            When the client acknowledges a pending challenge
            Then the ACME server MUST begin validating that challenge
            And the immediate challenge response MUST reflect a state of "pending" or "processing"
            And only the account that owns the authorization MUST be allowed to acknowledge the challenge

        @acme-item5
        Scenario: RFC 8555 Section 7.5 permits authorization deactivation
            When the client POSTs an authorization object with status "deactivated" to its authorization URL
            Then the ACME server MUST deactivate the authorization
            And the returned authorization object MUST have status "deactivated"

        @acme-item5
        Scenario: RFC 8555 requires embedded challenge and order errors to use ACME problem URNs
            When challenge validation fails
            Then the challenge error object MUST use an "urn:ietf:params:acme:error:" URN
            And the order error object MUST use an "urn:ietf:params:acme:error:" URN

        Scenario: RFC 8555 Section 8 requires challenge tokens to be random and URL-safe
            When the ACME server generates a challenge token
            Then the token MUST contain at least 128 bits of entropy
            And the token MUST be base64url encoded without padding

    Rule: Identifier validation methods

        @acme-item5
        Scenario: RFC 8555 Section 8.3 defines http-01 validation for non-wildcard DNS identifiers
            Given the ACME server offers the "http-01" challenge for a non-wildcard DNS identifier
            When the client provisions the HTTP challenge response
            Then the ACME server MUST fetch "http://{identifier}/.well-known/acme-challenge/{token}"
            And the response body MUST equal the challenge token followed by "." and the account key thumbprint
            And a successful validation MUST transition the challenge and authorization to "valid"

        @acme-item5
        Scenario: RFC 8555 Section 8.4 defines dns-01 validation
            Given the ACME server offers the "dns-01" challenge
            When the client provisions the DNS TXT challenge response
            Then the ACME server MUST query the "_acme-challenge" TXT record for the identifier
            And the TXT value MUST equal the base64url-encoded SHA-256 digest of the key authorization
            And a successful validation MUST transition the challenge and authorization to "valid"

        @acme-item5
        Scenario: RFC 8555 Section 7.5 requires failed challenge validation to invalidate the authorization
            When challenge validation fails
            Then the ACME server MUST mark the challenge "invalid"
            And the ACME server MUST mark the authorization "invalid"
            And the challenge or authorization object MUST expose the validation error

    Rule: Finalization and certificate issuance

        @acme-item4
        Scenario: RFC 8555 Section 7.4 requires the order to become ready before finalization
            When not all authorizations for an order are valid
            Then the ACME server MUST NOT finalize the order
            And the order MUST remain "pending" or become "invalid"

        @acme-item4
        Scenario: RFC 8555 Section 7.4 requires CSR submission to the finalize URL
            When the client finalizes a ready order
            Then the request body MUST contain a base64url-encoded CSR
            And the ACME server MUST verify that the identifiers requested in the CSR match the order's identifiers
            And the ACME server MUST reject a malformed or unacceptable CSR

        @acme-item4
        Scenario: RFC 8555 Section 7.4 requires CSRs without subjectAltName entries to be rejected
            When the client finalizes a ready order with a CSR that has no subjectAltName extension
            Then the ACME server MUST reject the request with the "badCSR" ACME error type

        @acme-item4
        Scenario: RFC 8555 Section 7.4 requires CSR identifiers to match the order exactly
            When the client finalizes a ready order with a CSR whose identifiers do not exactly match the order
            Then the ACME server MUST reject the request with the "badCSR" ACME error type

        @acme-item4
        Scenario: RFC 8555 Section 7.4 allows successful finalization to return processing or valid
            When the ACME server accepts a CSR for a ready order
            Then the response MUST return the order object
            And the order status MUST become either "processing" or "valid"
            And if issuance is not complete the ACME server MAY include a Retry-After header

        @acme-item4
        Scenario: RFC 8555 Section 7.4 requires orders that cannot be issued to become invalid
            When certificate issuance fails after finalization
            Then the ACME server MUST mark the order "invalid"
            And the order object MUST contain an error object explaining the failure

        @acme-item4
        Scenario: RFC 8555 Sections 7.1.3 and 7.4 require accepted notBefore and notAfter values to be enforced during issuance
            When the client finalizes a ready order with accepted notBefore and notAfter values
            Then the issued certificate MUST honor the accepted notBefore value
            And the issued certificate MUST honor the accepted notAfter value

    Rule: Certificate retrieval

        Scenario: RFC 8555 Section 7.4.2 requires certificate URLs to be retrievable with POST-as-GET
            Given the order status is "valid"
            When the client fetches the certificate URL
            Then the ACME server MUST return the issued certificate chain
            And the response content type MUST be "application/pem-certificate-chain"

        Scenario: RFC 8555 Section 7.4.2 allows alternate certificate chains
            When the ACME server can provide alternate certificate chains for the same order
            Then the response MAY include Link headers with relation "alternate"

    Rule: Certificate revocation

        Scenario: RFC 8555 Section 7.6 defines certificate revocation when the server supports it
            Given the ACME server implements the "revokeCert" resource
            When the client revokes a certificate using the account that issued it
            Then the ACME server MUST accept the revocation request
            And a successful revocation MUST return status code 200

        Scenario: RFC 8555 Section 7.6 also allows revocation using the certificate's private key
            Given the ACME server implements the "revokeCert" resource
            When the client revokes a certificate using the certificate's private key
            Then the ACME server MUST accept the revocation request if the signature is valid

        Scenario: RFC 8555 Section 7.6 requires authorization checks on revocation
            Given the ACME server implements the "revokeCert" resource
            When an unauthorized account attempts to revoke a certificate
            Then the ACME server MUST reject the revocation request

    Rule: Account key rollover

        @acme-item6
        Scenario: RFC 8555 Section 7.3.5 defines account key rollover when the server supports it
            Given the ACME server implements the "keyChange" resource
            When the client requests account key rollover
            Then the outer JWS MUST be signed by the new account key
            And the inner JWS MUST be signed by the old account key
            And the inner payload MUST identify the same account URL as the outer request
            And the ACME server MUST verify that the old key currently controls the account
            And the ACME server MUST reject attempts to roll an account key to a key already in use by another account

        @acme-item6
        Scenario: RFC 8555 Section 7.3.5 requires the new key to authorize subsequent requests
            Given the ACME server implements the "keyChange" resource
            When account key rollover succeeds
            Then subsequent requests signed with the new key MUST be accepted
            And subsequent requests signed only with the old key MUST be rejected

