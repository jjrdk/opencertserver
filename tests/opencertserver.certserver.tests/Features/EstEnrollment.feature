Feature: Est enrollment
Enrollment over secure transport using JWT

    Background:
        Given a certificate server
        And an EST client

    Scenario: Enroll with JWT
        When I enroll with a valid JWT
        Then I should get a certificate

    Scenario: Re-Enroll with JWT
        When I enroll with a valid JWT
        And I get a certificate
        And I use the certificate to re-enroll without a valid JWT
        Then I should get a new certificate
