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

    # Windows creates RSA keys for SCEP. The CA core issues only when the request key
    # matches the CA key algorithm (CertificateAuthority.SignCertificateRequest), so an
    # ECDSA profile cannot serve SCEP clients today. This scenario pins that behaviour.
    Scenario: An RSA request against an ECDSA profile is refused by the CA
        Given a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "geheim" using the "ecdsa" profile
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

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
