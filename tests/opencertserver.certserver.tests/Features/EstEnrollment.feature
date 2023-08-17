Feature: Est enrollment
Enrollment over secure transport using JWT

    Background:
        Given a certificate server
        And an EST client

    Scenario: Enroll with JWT
        And the second number is 70
        When the two numbers are added
        Then the result should be 120
