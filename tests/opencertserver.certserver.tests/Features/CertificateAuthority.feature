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

    Scenario: Certificate query
        When I enroll with a valid JWT
        And I get a certificate
        And I query the certificate inventory
        Then the certificate should be included in the inventory
