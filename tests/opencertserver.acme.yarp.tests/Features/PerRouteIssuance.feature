Feature: Per-route issuance triggers distinct orders and serves separate certificates

    As a YARP host with multiple ACME-tagged routes
    I want each route to place its own ACME order and serve its own leaf
    So that two routes never share a single certificate or a single order

    Background:
        Given the YARP route "route.alpha" for host "alpha.example.com"
        And the YARP route "route.beta" for host "beta.example.com"

    Scenario: Each ACME route places its own order and serves its own certificate
        When the renewal service runs against a recording ACME client
        Then two distinct ACME orders were placed
        And the order for route "route.alpha" requested host "alpha.example.com"
        And the order for route "route.beta" requested host "beta.example.com"
        And Kestrel serves the route "route.alpha" certificate to host "alpha.example.com"
        And Kestrel serves the route "route.beta" certificate to host "beta.example.com"
        And the two routes serve different certificates
