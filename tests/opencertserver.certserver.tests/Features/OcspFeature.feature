Feature: OCSP lookup

    Background:
        Given a certificate server
        And an EST client

    Scenario: Certificate revocation
        When I enroll with a valid JWT
        And I get a certificate
        Then the certificate should be valid in OCSP
        When I revoke the certificate
        Then the certificate should be revoked in OCSP

    Scenario: Unknown certificate
        When I check OCSP for an unknown certificate
        Then the response should indicate the certificate is unknown
