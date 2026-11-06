Feature: Certificate lifecycle management

    Scenario Outline: Empty CRL
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I check the initial CRL
        Then the CRL should be empty

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: Certificate revocation
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I enroll with a valid JWT
        And I get a certificate
        And I revoke the certificate
        Then the certificate should be in the CRL

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: Unauthorized cross-certificate revocation is rejected
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I enroll with a valid JWT
        And I get a certificate
        And I try to revoke the certificate with a different key
        Then the revocation should be rejected with status Forbidden

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: Revocation with a crafted certificate of matching serial is rejected
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I enroll with a valid JWT
        And I get a certificate
        And I try to revoke the certificate with a crafted certificate of the same serial
        Then the revocation should be rejected with status Forbidden

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: Admin can revoke any certificate
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I enroll with a valid JWT
        And I get a certificate
        And an admin revokes the certificate with a different key
        Then the certificate should be in the CRL

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # /ca/csr threw before the handler ran: it asked for a route parameter the route does
    # not define. Nothing called the endpoint in the suite, so the 500 went unnoticed.
    Scenario Outline: A PEM request is signed over the CA endpoint
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I post a PEM certificate request to "<path>" with a valid JWT
        Then the response is a PEM chain issued by the "<profile>" profile

        Examples:
          | path         | profile | Storage    |
          | ca/csr       | rsa     | in-memory  |
          | ca/csr       | rsa     | postgresql |
          | ca/csr       | rsa     | mssql      |
          | ca/ecdsa/csr | ecdsa   | in-memory  |
          | ca/ecdsa/csr | ecdsa   | postgresql |
          | ca/ecdsa/csr | ecdsa   | mssql      |

    Scenario Outline: A profile signs requests of either key algorithm
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When the CA signs a <request key> certificate request with the "<profile>" profile
        Then the issued certificate carries the key of the request
        And the issued certificate is signed with the <signature> algorithm
        And the issued certificate chains to the "<profile>" CA

        Examples:
          | request key | profile | signature               | Storage    |
          | RSA         | rsa     | sha256WithRSAEncryption | in-memory  |
          | RSA         | rsa     | sha256WithRSAEncryption | postgresql |
          | RSA         | rsa     | sha256WithRSAEncryption | mssql      |
          | RSA         | ecdsa   | ecdsa-with-SHA256       | in-memory  |
          | RSA         | ecdsa   | ecdsa-with-SHA256       | postgresql |
          | RSA         | ecdsa   | ecdsa-with-SHA256       | mssql      |
          | ECDSA       | rsa     | sha256WithRSAEncryption | in-memory  |
          | ECDSA       | rsa     | sha256WithRSAEncryption | postgresql |
          | ECDSA       | rsa     | sha256WithRSAEncryption | mssql      |
          | ECDSA       | ecdsa   | ecdsa-with-SHA256       | in-memory  |
          | ECDSA       | ecdsa   | ecdsa-with-SHA256       | postgresql |
          | ECDSA       | ecdsa   | ecdsa-with-SHA256       | mssql      |
