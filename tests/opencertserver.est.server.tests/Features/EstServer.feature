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

    Scenario Outline: Failed enrollment of a new certificate
        Given a certificate server that complies with EST (RFC 7030)
        When an unauthenticated client submits a valid <profile> certificate signing request (CSR)
        Then the server should return an error message indicating the reason for the failure

        Example: CSR Profile
          | profile |
          | rsa     |
          | ecdsa   |

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
