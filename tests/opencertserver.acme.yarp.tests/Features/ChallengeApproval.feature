Feature: ACME challenge approval middleware

    As a host of the ACME client middleware
    I want HTTP-01 challenges to be served per-route
    So that any route that receives a challenge token can prove domain control

    Background:
        Given a middleware that serves the known token "tok-abc" with response "tok-abc-keyauthz-response"

    Scenario: A known challenge token resolves for any route
        When I request the ACME challenge path for token "tok-abc"
        Then the approval response status code should be 200
        And the approval response body should be "tok-abc-keyauthz-response"

    Scenario: An unknown challenge token yields 410 Gone
        When I request the ACME challenge path for token "doesnotexist"
        Then the approval response status code should be 410
