Feature: Certificate server compliance with EST (RFC 7030)

    Scenario: Successful enrollment of a new RSA certificate
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid RSA certificate signing request (CSR)
        Then the server returns a signed certificate

    Scenario: Successful enrollment of a new ECDsa certificate
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid ECDsa certificate signing request (CSR)
        Then the server returns a signed certificate

    Scenario: Successful re-enrollment of a new RSA certificate
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid RSA certificate signing request (CSR)
        And the server returns a signed certificate
        And the RSA client uses the previously issued certificate for re-enrollment
        Then the server returns a signed certificate

    Scenario: Successful re-enrollment of a new ECDsa certificate
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid ECDsa certificate signing request (CSR)
        And the server returns a signed certificate
        And the ECDsa client uses the previously issued certificate for re-enrollment
        Then the server returns a signed certificate

    Scenario: Failed enrollment of a new RSA certificate
        Given a certificate server that complies with EST (RFC 7030)
        When an unauthenticated client submits a valid RSA certificate signing request (CSR)
        Then the server should return an error message indicating the reason for the failure

    Scenario: Failed enrollment of a new ECDsa certificate
        Given a certificate server that complies with EST (RFC 7030)
        When an unauthenticated client submits a valid ECDsa certificate signing request (CSR)
        Then the server should return an error message indicating the reason for the failure

    Scenario: Failed enrollment due to invalid CSR
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits an invalid CSR
        Then the server should return an error message indicating the reason for the failure

    Scenario: Successful retrieval of CA certificates
        Given a certificate server that complies with EST (RFC 7030)
        When a client requests the CA certificates
        Then the server should return the CA certificates in the correct format

    Scenario: Successful retrieval of server attributes
        Given a certificate server that complies with EST (RFC 7030)
        When an authenticated client requests the server attributes
        Then the server should return the server attributes in the correct format
