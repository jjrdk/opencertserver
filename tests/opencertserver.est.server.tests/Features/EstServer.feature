Feature: Certificate server compliance with EST (RFC 7030)

    Scenario Outline: Successful enrollment of a new certificate using the profile
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid <profile> certificate signing request (CSR) using the "<profile>" certificate profile
        Then the server returns a signed certificate

        Examples:
          | profile |
          | rsa     |
          | ecdsa   |

    Scenario Outline: Enrollment honors the extensions requested in the CSR
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid <profile> certificate signing request (CSR) using the "<profile>" certificate profile
        Then the issued certificate contains the key usage extension requested in the CSR

        Examples:
          | profile |
          | rsa     |
          | ecdsa   |

    Scenario Outline: Enrollment honors the subject alternative name URI requested in the CSR
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid <profile> certificate signing request (CSR) containing a SAN URI using the "<profile>" certificate profile
        Then the issued certificate contains the SAN URI requested in the CSR

        Examples:
          | profile |
          | rsa     |
          | ecdsa   |

    Scenario Outline: Enrollment tolerates the encodings RFC 7030 and RFC 8951 allow for the CSR
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid <profile> CSR containing a SAN URI encoded as <encoding> using the "<profile>" certificate profile
        Then the issued certificate contains the SAN URI requested in the CSR

        Examples:
          | profile | encoding                |
          | rsa     | base64 with line breaks |
          | rsa     | base64 with spaces      |
          | rsa     | PEM                     |
          | ecdsa   | base64 with spaces      |
          | ecdsa   | PEM                     |

    Scenario Outline: Successful re-enrollment of a new certificate
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid <profile> certificate signing request (CSR) using the "<profile>" certificate profile
        And the server returns a signed certificate
        And the <profile> client uses the previously issued certificate for re-enrollment
        Then the server returns a signed certificate
        And the response contains only the issued certificate

        Examples:
          | profile |
          | RSA     |
          | ECDsa   |

    Scenario Outline: Re-enrollment with a revoked certificate is refused
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid <profile> certificate signing request (CSR) using the "<profile>" certificate profile
        And the server returns a signed certificate
        And the issued certificate is revoked
        And the <profile> client uses the previously issued certificate for re-enrollment
        Then the server should return an error message indicating the reason for the failure

        Examples:
          | profile |
          | RSA     |
          | ECDsa   |

    Scenario Outline: Successful re-enrollment of a certificate that carries a subject alternative name
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid <profile> certificate signing request (CSR) containing a SAN URI using the "<profile>" certificate profile
        And the client re-enrolls the issued certificate with the same subject and subject alternative name
        Then the server returns a signed certificate
        And the issued certificate contains the SAN URI requested in the CSR

        Examples:
          | profile |
          | rsa     |
          | ecdsa   |

    Scenario Outline: Failed enrollment of a new certificate
        Given a certificate server that complies with EST (RFC 7030)
        When an unauthenticated client submits a valid <profile> certificate signing request (CSR)
        Then the server should return an error message indicating the reason for the failure

        Example: CSR Profile
          | profile |
          | rsa     |
          | ecdsa   |

    Scenario Outline: Enrollment issues a certificate for the authenticated client's own name
        Given a certificate server that complies with EST (RFC 7030)
        When a client authenticated as "CN=test" requests a <profile> certificate for the subject "CN=test"
        Then the server returns a signed certificate

        Examples:
          | profile |
          | rsa     |
          | ecdsa   |

    Scenario Outline: Enrollment refuses a certificate for a name other than the authenticated client's
        Given a certificate server that complies with EST (RFC 7030)
        When a client authenticated as "CN=test" requests a <profile> certificate for the subject "CN=someone else"
        Then the server should return an error message indicating the reason for the failure

        Examples:
          | profile |
          | rsa     |
          | ecdsa   |

    Scenario Outline: Enrollment refuses a subject alternative name the authenticated client does not carry
        Given a certificate server that complies with EST (RFC 7030)
        When a client authenticated as "CN=test" requests a <profile> certificate for the subject "CN=test" with the <san> "someone.else@example.org"
        Then the server should return an error message indicating the reason for the failure

        Examples:
          | profile | san                 |
          | rsa     | rfc822Name          |
          | ecdsa   | user principal name |

    Scenario: Failed enrollment due to invalid CSR
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits an invalid CSR
        Then the server should return an error message indicating the reason for the failure

    Scenario Outline: Successful retrieval of CA certificates for the profile
        Given a certificate server that complies with EST (RFC 7030)
        When a client requests the CA certificates for the "<profile>" certificate profile
        Then the server should return the CA certificates in the correct format

        Examples:
          | profile |
          | rsa     |
          | ecdsa   |

    Scenario Outline: Successful retrieval of server attributes for the profile
        Given a certificate server that complies with EST (RFC 7030)
        When an authenticated client requests the server attributes for the <profile> certificate profile
        Then the server should return the server attributes in the correct format

        Examples:
          | profile |
          | rsa     |
          | ecdsa   |

    Scenario Outline: Server-side key generation treats the CSR like any enroll CSR
        Given a certificate server that complies with EST (RFC 7030)
        When a client requests server-side key generation with a <profile> CSR for a <size> key containing a SAN URI and key usage
        Then the server-generated key is a <profile> key of size <size>
        And the certificate part is a certs-only response containing only the issued certificate
        And the issued certificate belongs to the server-generated key
        And the issued certificate contains the SAN URI requested in the CSR
        And the issued certificate contains the key usage extension requested in the CSR

        Examples:
          | profile | size |
          | rsa     | 3072 |
          | ecdsa   | 384  |

    Scenario: A client certificate issued by an explicitly configured trust anchor can enroll
        Given an EST server configured with an external client trust anchor
        When a client certificate from the external CA enrolls
        Then the server returns a signed certificate

    Scenario: A client certificate issued by an unconfigured trust anchor cannot enroll
        Given an EST server without the external client trust anchor
        When a client certificate from the external CA enrolls
        Then the enrollment is refused

    Scenario: An EST trust anchor does not authenticate a client on a non-EST route
        Given an EST server configured with an external client trust anchor
        When a client certificate from the external CA enrolls
        And the external client certificate accesses a non-EST route
        Then the server returns a signed certificate
        And the client is not authenticated on the non-EST route

    Scenario: A profile trust anchor authenticates its own and the default profile only
        Given an EST server with an external client trust anchor only in the rsa profile
        When a client certificate from the external CA enrolls in profile "rsa"
        Then the server returns a signed certificate
        When the default profile is requested by the external client
        And a client certificate from the external CA enrolls in profile "ecdsa"
        Then the enrollment is refused

    Scenario: A profile trust anchor does not authenticate a client on a non-EST route
        Given an EST server with an external client trust anchor only in the rsa profile
        When a client certificate from the external CA enrolls
        And the external client certificate accesses a non-EST route
        Then the server returns a signed certificate
        And the client is not authenticated on the non-EST route

    Scenario Outline: Server-wide trust anchors apply to every profile
        Given an EST server configured with an external client trust anchor
        When a client certificate from the external CA enrolls in profile "<profile>"
        Then the server returns a signed certificate
        And cacerts publishes the issuing chain but not the external client trust anchor for profile "<profile>"

        Examples:
          | profile |
          | rsa     |
          | ecdsa   |

    Scenario: Profile client trust anchors are not published as issuing trust
        Given an EST server with an external client trust anchor only in the rsa profile
        Then cacerts publishes the issuing chain but not the external client trust anchor for profile "rsa"

    Scenario Outline: Explicit roots and untrusted intermediates have distinct roles
        Given an EST server with an external client intermediate and "<trust>" trust
        When a client certificate from the external CA enrolls in profile "<profile>"
        Then the server returns a signed certificate

        Examples:
          | trust               | profile |
          | profile             | rsa     |
          | server-wide         | rsa     |
          | server-wide         | ecdsa   |
          | shared root         | rsa     |
          | shared intermediate | rsa     |

    Scenario: An additional chain certificate does not independently establish trust
        Given an EST server with an external client intermediate and "no root" trust
        When a client certificate from the external CA enrolls
        Then the enrollment is refused

    Scenario: A profile intermediate cannot leak trust into another profile
        Given an EST server with an external client intermediate and "profile" trust
        When a client certificate from the external CA enrolls in profile "ecdsa"
        Then the enrollment is refused

    Scenario: A shared intermediate does not share a profile-specific trust anchor
        Given an EST server with an external client intermediate and "shared intermediate" trust
        When a client certificate from the external CA enrolls in profile "ecdsa"
        Then the enrollment is refused
