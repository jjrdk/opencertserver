Feature: Certificate server compliance with EST (RFC 7030)

    Scenario: Successful enrollment of a new certificate
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid certificate signing request (CSR)
        Then the server should return a signed certificate

    Scenario: Failed enrollment due to invalid CSR
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits an invalid CSR
        Then the server should return an error message indicating the reason for the failure

    Scenario: Successful retrieval of CA certificates
        Given a certificate server that complies with EST (RFC 7030)
        When a client requests the CA certificates
        Then the server should return the CA certificates in the correct format

    Scenario: Failed retrieval of CA certificates due to unauthorized access
        Given a certificate server that complies with EST (RFC 7030)
        When an unauthorized client requests the CA certificates
        Then the server should return an error message indicating that access is denied
