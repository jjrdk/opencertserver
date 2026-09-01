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

    Scenario Outline: Successful re-enrollment of a new certificate
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid <profile> certificate signing request (CSR) using the "<profile>" certificate profile
        And the server returns a signed certificate
        And the <profile> client uses the previously issued certificate for re-enrollment
        Then the server returns a signed certificate

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
