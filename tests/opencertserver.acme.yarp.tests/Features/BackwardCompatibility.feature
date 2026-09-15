Feature: Backward compatibility without a tagged YARP route

    As an existing single-listener user
    I want untagged usage to keep working
    So that the renewal service and SNI selector fall back to the default route

    Scenario: The renewal service loads the leaf from the default route scope
        Given a renewal service with no ACME-tagged route
        When I start the single-route renewal service
        Then a certificate is loaded for the default route

    Scenario: Kestrel serves the default leaf for any SNI host when no route is tagged
        Given the default route is served by a certificate
        When Kestrel selects a certificate for SNI host "anything.example.com"
        Then the selected certificate is the default leaf
