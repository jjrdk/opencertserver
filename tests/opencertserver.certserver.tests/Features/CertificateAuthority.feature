Feature: Certificate lifecycle management

    Background:
        Given a certificate server
        And an EST client

    Scenario: Empty CRL
        When I check the initial CRL
        Then the CRL should be empty

    Scenario: Certificate revocation
        When I enroll with a valid JWT
        And I get a certificate
        And I revoke the certificate
        Then the certificate should be in the CRL

    Scenario: Unauthorized cross-certificate revocation is rejected
        When I enroll with a valid JWT
        And I get a certificate
        And I try to revoke the certificate with a different key
        Then the revocation should be rejected with status Forbidden

    Scenario: Revocation with a crafted certificate of matching serial is rejected
        When I enroll with a valid JWT
        And I get a certificate
        And I try to revoke the certificate with a crafted certificate of the same serial
        Then the revocation should be rejected with status Forbidden

    Scenario: Admin can revoke any certificate
        When I enroll with a valid JWT
        And I get a certificate
        And an admin revokes the certificate with a different key
        Then the certificate should be in the CRL

    # /ca/csr threw before the handler ran: it asked for a route parameter the route does
    # not define. Nothing called the endpoint in the suite, so the 500 went unnoticed.
    Scenario Outline: A PEM request is signed over the CA endpoint
        When I post a PEM certificate request to "<path>" with a valid JWT
        Then the response is a PEM chain issued by the "<profile>" profile

        Examples:
          | path         | profile |
          | ca/csr       | rsa     |
          | ca/ecdsa/csr | ecdsa   |

    Scenario Outline: A profile signs requests of either key algorithm
        When the CA signs a <request key> certificate request with the "<profile>" profile
        Then the issued certificate carries the key of the request
        And the issued certificate is signed with the <signature> algorithm
        And the issued certificate chains to the "<profile>" CA

        Examples:
          | request key | profile | signature               |
          | RSA         | rsa     | sha256WithRSAEncryption |
          | RSA         | ecdsa   | ecdsa-with-SHA256       |
          | ECDSA       | rsa     | sha256WithRSAEncryption |
          | ECDSA       | ecdsa   | ecdsa-with-SHA256       |
