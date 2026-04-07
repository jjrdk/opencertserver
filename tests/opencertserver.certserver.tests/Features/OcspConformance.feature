@ocsp
@rfc6960
Feature: OCSP conformance
Server-relevant OCSP conformance requirements from RFC 6960.
The scenarios below inventory the responder behavior that the OpenCertServer OCSP implementation must satisfy.
They are intentionally written before adding step implementations so they can drive the OCSP work in TDD style.

    Background:
        Given a certificate server

    Rule: Responder endpoint and OCSP over HTTP

        Scenario: RFC 6960 requires OCSP responses to be returned as application/ocsp-response bodies
            When an OCSP client submits a DER-encoded OCSP request with HTTP POST
            Then the OCSP responder MUST return the "application/ocsp-response" media type
            And the OCSP response body MUST be DER encoded

        Scenario: RFC 6960 requires malformed OCSP requests to return the malformedRequest response status
            When an OCSP client submits a malformed OCSP request
            Then the OCSP responder MUST return the OCSP response status "malformedRequest"
            And the malformed request response MUST NOT include responseBytes

        Scenario: RFC 6960 allows internal responder failures to return internalError
            When the OCSP responder encounters an internal error while processing a request
            Then the OCSP responder MUST return the OCSP response status "internalError"
            And the internal error response MUST NOT include responseBytes

        Scenario: RFC 6960 allows temporary responder failures to return tryLater
            When the OCSP responder is temporarily unable to answer a request
            Then the OCSP responder MAY return the OCSP response status "tryLater"

        Scenario: RFC 6960 Appendix A allows OCSP GET for URL-safe base64 encoded requests
            When an OCSP client sends an OCSP request using HTTP GET with the request encoded into the request URI
            Then the OCSP responder MAY accept the GET request
            And if the GET request is accepted the OCSP responder MUST return the "application/ocsp-response" media type

        @strict-ocsp
        Scenario: Strict OCSP HTTP binding enforces application/ocsp-request content-type for POST requests
            When strict OCSP HTTP binding is enabled and an OCSP client submits a POST request with incorrect content-type
            Then the OCSP responder MUST return HTTP 400 Bad Request

    Rule: OCSP request syntax and request processing

        Scenario: RFC 6960 defines an OCSP request as a TBSRequest with one or more certificate requests
            When an OCSP client submits an OCSP request containing certificate status requests
            Then the OCSP responder MUST parse the TBSRequest requestList
            And the OCSP responder MUST evaluate every requested CertID

        Scenario: RFC 6960 defines CertID matching over issuer name hash issuer key hash and serial number
            When an OCSP client requests the status of a certificate by CertID
            Then the OCSP responder MUST match the request using the issuerNameHash value
            And the OCSP responder MUST match the request using the issuerKeyHash value
            And the OCSP responder MUST match the request using the serialNumber value

        Scenario: RFC 6960 requires one SingleResponse per requested certificate in a successful basic response
            When an OCSP client submits a successful OCSP request for multiple certificates
            Then the successful OCSP response MUST contain one SingleResponse for each requested CertID

        Scenario: RFC 6960 allows requestExtensions on the TBSRequest
            When an OCSP client includes requestExtensions in the TBSRequest
            Then the OCSP responder MUST process every supported request extension
            And the OCSP responder MUST reject unsupported critical request extensions

        Scenario: RFC 6960 allows singleRequestExtensions on each Request
            When an OCSP client includes singleRequestExtensions on an individual certificate request
            Then the OCSP responder MUST process every supported singleRequest extension
            And the OCSP responder MUST reject unsupported critical singleRequest extensions

        Scenario: RFC 6960 supports optional signed OCSP requests
            When an OCSP client submits a signed OCSP request
            Then the OCSP responder MAY accept the signed request
            And if the signed request is accepted the OCSP responder MUST validate the request signature

        Scenario: RFC 6960 allows a responder to require signed OCSP requests
            When the OCSP responder requires request signatures and the client sends an unsigned request
            Then the OCSP responder MUST return the OCSP response status "sigRequired"

        Scenario: RFC 6960 allows unauthorized to be returned for unacceptable signed requests
            When a signed OCSP request is not authorized by responder policy
            Then the OCSP responder MAY return the OCSP response status "unauthorized"

    Rule: Successful response structure

        Scenario: RFC 6960 requires a successful OCSP response to carry responseBytes
            When the OCSP responder successfully answers a certificate status request
            Then the OCSP response status MUST be "successful"
            And the OCSP response MUST include responseBytes
            And the responseBytes responseType MUST be id-pkix-ocsp-basic

        Scenario: RFC 6960 requires a BasicOCSPResponse to include tbsResponseData signatureAlgorithm and signature
            When the OCSP responder returns a successful basic OCSP response
            Then the BasicOCSPResponse MUST contain tbsResponseData
            And the BasicOCSPResponse MUST contain signatureAlgorithm
            And the BasicOCSPResponse MUST contain a cryptographic signature over the response data

        Scenario: RFC 6960 defines the responderID inside ResponseData
            When the OCSP responder returns a successful basic OCSP response
            Then the response data MUST contain a responderID
            And the responderID MUST identify the signer either by name or by key hash

        Scenario: RFC 6960 allows including responder certificates in the BasicOCSPResponse
            When the OCSP client needs certificates to verify the OCSP responder signature
            Then the BasicOCSPResponse MAY include responder certificates in the certs field

        Scenario: RFC 6960 defines the response data version as v1 by default
            When the OCSP responder returns a successful basic OCSP response
            Then the ResponseData version MUST default to v1 unless another version is explicitly encoded

    Rule: Certificate status values

        Scenario: RFC 6960 defines the good certificate status
            When the requested certificate is known and not revoked
            Then the corresponding SingleResponse MUST report the certificate status as good

        Scenario: RFC 6960 defines the revoked certificate status
            When the requested certificate has been revoked
            Then the corresponding SingleResponse MUST report the certificate status as revoked
            And the revoked response MUST include the revocationTime value
            And if the revocation reason is known the response SHOULD include the revocationReason value

        Scenario: RFC 6960 defines the unknown certificate status
            When the responder cannot determine the status of the requested certificate
            Then the corresponding SingleResponse MUST report the certificate status as unknown

        Scenario: RFC 6960 allows the extended revoked model for non-issued certificates when explicitly supported
            When the OCSP responder uses the extended revoked definition for a non-issued certificate
            Then the corresponding successful response MUST comply with the RFC 6960 extended revoked requirements

    Rule: Response freshness and time values

        Scenario: RFC 6960 requires producedAt on successful basic responses
            When the OCSP responder returns a successful basic response
            Then the response data MUST include the producedAt timestamp

        Scenario: RFC 6960 requires thisUpdate on every SingleResponse
            When the OCSP responder returns a SingleResponse
            Then the SingleResponse MUST include the thisUpdate timestamp

        Scenario: RFC 6960 allows nextUpdate on SingleResponse values
            When the OCSP responder provides a next update time for a certificate status
            Then the SingleResponse MAY include nextUpdate
            And if nextUpdate is present it MUST NOT be earlier than thisUpdate

        Scenario: RFC 6960 requires the responder to base status information on sufficiently recent revocation data
            When the OCSP responder returns certificate status information
            Then the responder MUST base the response on current revocation information according to local freshness policy

        @custom-ocsp-freshness
        Scenario: OCSP responder freshness policy is configurable
            When the OCSP responder uses a custom freshness window of 2 hours
            Then the SingleResponse nextUpdate MUST be thisUpdate plus 2 hours

    Rule: Authorized responder and signature verification requirements

        Scenario: RFC 6960 requires successful OCSP responses to be signed by an authorized responder
            When the OCSP responder returns a successful basic response
            Then the response signature MUST be generated by the issuing CA or by a delegated OCSP signing certificate authorized by that CA

        Scenario: RFC 6960 defines the delegated OCSP responder certificate requirements
            When a delegated OCSP responder certificate signs the response
            Then the delegated certificate MUST be issued directly by the CA that issued the certificate being checked
            And the delegated certificate MUST assert the id-kp-OCSPSigning extended key usage

        Scenario: RFC 6960 requires clients to be able to identify the signer from the response and available certificates
            When the OCSP responder includes certificates in the response
            Then the included certificates MUST be sufficient for a client to build and validate the authorized responder chain according to responder policy

    Rule: OCSP request and response extensions

        Scenario: RFC 6960 defines the OCSP nonce extension
            When an OCSP client includes an OCSP nonce extension in the request
            Then a nonce-supporting OCSP responder SHOULD include a matching nonce extension in the corresponding response

        Scenario: RFC 6960 allows the archive cutoff extension
            When the OCSP responder provides status for certificates beyond the responder's normal retention window
            Then the OCSP responder MAY include the archiveCutoff response extension

        Scenario: RFC 6960 defines the service locator extension
            When an OCSP request includes the serviceLocator extension
            Then a supporting responder MAY use that extension to locate the authoritative responder for the requested certificate

        Scenario: RFC 6960 defines the preferred signature algorithms extension
            When an OCSP request includes the preferred signature algorithms extension
            Then a supporting responder SHOULD choose a response signature algorithm compatible with the client's preference list

    Rule: OCSP response semantics for multiple requests and unsupported inputs

        Scenario: RFC 6960 requires the responder to preserve status semantics independently for each requested certificate
            When an OCSP request contains certificates in different states
            Then each SingleResponse MUST report the correct status for its own CertID independent of the other requests

        Scenario: RFC 6960 requires unsupported response types to be rejected by clients and only basic responses to be generated here
            When the OCSP responder returns a successful response
            Then the responder MUST use the id-pkix-ocsp-basic response type unless another standardized response type is intentionally implemented

        Scenario: RFC 6960 requires an unauthorized response when the server refuses service to the client or target domain
            When responder policy refuses to answer a status request
            Then the OCSP responder MAY return the OCSP response status "unauthorized"
