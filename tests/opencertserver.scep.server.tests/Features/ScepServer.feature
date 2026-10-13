Feature: Certificate server compliance with SCEP (RFC 8894)

    Scenario: The server announces its capabilities
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client asks for the CA capabilities
        Then the capabilities include "POSTPKIOperation", "SHA-256" and "AES"

    Scenario: The server publishes the RA certificate before the CA certificate
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client asks for the CA certificates
        Then the response is a CA/RA certificate bundle
        And the first certificate is the RA certificate
        And the bundle contains the CA certificate

    # Below a root, GetCACert carries the published chain, root included. Windows looks
    # for the root thumbprint of its Intune profile in this response and gives up before
    # sending a request when it is missing ("The hash value is not correct", 0x80091007).
    Scenario: The server publishes the root above an issuing CA
        Given a certificate server with SCEP whose CA is issued by a root
        When a client asks for the CA certificates
        Then the first certificate is the RA certificate
        And the bundle contains the CA certificate
        And the bundle contains the root certificate

    Scenario Outline: Enrollment with the right challenge password
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "<challenge>" using the "<profile>" profile
        Then the server answers SUCCESS
        And the response echoes the transaction ID and the client's nonce
        And the issued certificate has the requested subject
        And the issued certificate is issued by the "<profile>" CA

        Examples:
          | profile | challenge |
          | rsa     | geheim    |

    # Windows creates RSA keys for SCEP. Since #111 the CA signs a request whose key
    # algorithm differs from its own, so an ECDSA profile can serve SCEP clients.
    Scenario: An RSA request against an ECDSA profile is issued by the CA
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "geheim" using the "ecdsa" profile
        Then the server answers SUCCESS
        And the issued certificate is issued by the "ecdsa" CA

    Scenario: Enrollment through GET
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls through GET with the challenge password "geheim"
        Then the server answers SUCCESS

    Scenario: A wrong challenge password is refused
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "falsch" using the "rsa" profile
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    Scenario: A request without a challenge password is refused
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls without a challenge password
        Then the server answers FAILURE with failInfo badRequest

    Scenario: A request encrypted to a key other than the RA is rejected
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with a request encrypted to a foreign certificate
        Then the server rejects the message with HTTP 400

    Scenario: The user principal name from the request is carried into the certificate
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with a subject alternative name UPN "anna@example.at"
        Then the server answers SUCCESS
        And the issued certificate contains the UPN "anna@example.at"

    # Whoever knew the challenge used to get a subordinate CA: the CA core took
    # basicConstraints CA:TRUE and keyCertSign over from the CSR.
    Scenario: A request for a CA certificate is refused
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls asking for basicConstraints CA:TRUE and keyCertSign
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    Scenario: The server offers renewal
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client asks for the CA capabilities
        Then the capabilities include "Renewal", "SHA-256" and "AES"

    # RFC 8894, 3.3.1.2: a RenewalReq is signed with the certificate it renews. That
    # certificate is the proof - no challenge password is needed.
    Scenario: A certificate is renewed with the certificate it replaces
        Given a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile
        When the client renews it with a new key
        Then the server answers SUCCESS
        And the renewed certificate has the same subject and a new key
        And the previous certificate is revoked

    # The CA core accepts reenrollingFrom by issuer name alone (#96). A certificate signed
    # by another key under the same CA name must not pass as proof.
    Scenario: A renewal signed with a look-alike certificate is refused
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client renews with a certificate from a look-alike CA of the same name
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    Scenario: A renewal for another subject is refused
        Given a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile
        When the client renews it for the subject "CN=Anderes Geraet, O=entra-vpn"
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    # As for EST simplereenroll (RFC 7030, 4.2.2): the renewal names what the certificate
    # it renews names. The profile copies the subjectAltName from the request.
    Scenario: A certificate with a subject alternative name is renewed with the same name
        Given a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile with the UPN "anna@contoso.test"
        When the client renews it with the UPN "anna@contoso.test"
        Then the server answers SUCCESS
        And the renewed certificate has the same subject and a new key

    Scenario: A renewal for another subject alternative name is refused
        Given a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile with the UPN "anna@contoso.test"
        When the client renews it with the UPN "bert@contoso.test"
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    Scenario: A renewal that drops the subject alternative name is refused
        Given a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile with the UPN "anna@contoso.test"
        When the client renews it without a subject alternative name
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    Scenario: A renewal with a revoked certificate is refused
        Given a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile
        And that certificate is revoked
        When the client renews it with a new key
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    # A captured request must not have the CA issue a second time.
    Scenario: A replayed transaction is refused
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "geheim" using the "rsa" profile
        And the same request is sent again
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    # certserver wires SCEP in by default. Until a challenge is configured, the endpoint
    # publishes its certificates but issues nothing.
    Scenario: A server without a challenge validator issues nothing
        Given a certificate server with SCEP but no challenge validator
        When a client enrolls with the challenge password "geheim" using the "rsa" profile
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    # RFC 8894, 3.5.2: the capability "AES" promises AES128-CBC, and 2.9 makes it
    # mandatory. The reply is encrypted with the algorithm the request used, so a
    # client always gets back what it can read - including an old one on triple DES.
    Scenario Outline: The reply is encrypted with the algorithm of the request
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "geheim" and the request encrypted with "<algorithm>"
        Then the server answers SUCCESS
        And the reply is encrypted with "<algorithm>"

        Examples:
          | algorithm   |
          | AES-128-CBC |
          | AES-256-CBC |
          | 3DES-CBC    |

    # RFC 8894, 3.2.1: senderNonce is a 16-byte random number.
    Scenario: A senderNonce that is not 16 bytes is refused
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with a senderNonce of 8 bytes
        Then the server answers HTTP 400
