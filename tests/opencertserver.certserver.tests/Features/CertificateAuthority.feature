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
