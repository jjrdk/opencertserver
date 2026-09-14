Feature: Per-route ACME registration

    As a YARP host
    I want each ACME-enabled route to register an ACME certificate
    So that a distinct leaf is issued per route

    Scenario: Each ACME route registers a distinct descriptor
        Given an ACME route "route.alpha" for host "alpha.example.com"
        And an ACME route "route.beta" for host "beta.example.com"
        When the ACME config filter processes the routes
        Then route "route.alpha" contains host "alpha.example.com"
        And route "route.beta" contains host "beta.example.com"

    Scenario: A route without ACME metadata does not register
        Given an ACME route "route.alpha" for host "alpha.example.com"
        And a plain route "route.beta" for host "beta.example.com"
        When the ACME config filter processes the routes
        Then exactly one ACME route is registered

    Scenario: Route hosts map to certificate SANs
        Given an ACME route "route.multi" for hosts "multi1.example.com, multi2.example.com"
        When the ACME config filter processes the routes
        Then route "route.multi" contains 2 hosts
        And route "route.multi" contains host "multi1.example.com"
        And route "route.multi" contains host "multi2.example.com"
