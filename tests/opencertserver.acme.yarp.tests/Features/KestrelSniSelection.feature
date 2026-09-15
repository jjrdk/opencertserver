Feature: Kestrel SNI certificate selection

    As a multi-host host
    I want the correct certificate selected per host via SNI
    So that each route serves its own leaf

    Scenario: SNI selects the certificate whose host is in the route
        Given route "route.alpha" serves "alpha.example.com"
        And route "route.beta" serves "beta.example.com"
        When Kestrel selects a certificate for SNI host "alpha.example.com"
        Then the selected certificate is the certificate for "route.alpha"

    Scenario: SNI rejects an unknown host with a default fallback
        Given the default route is served by a certificate
        And route "route.alpha" serves "alpha.example.com"
        When Kestrel selects a certificate for SNI host "unknown.example.com"
        Then the selected certificate is the default leaf

    Scenario: A renewed certificate is picked up on the next handshake
        Given route "route.alpha" serves "alpha.example.com"
        When Kestrel selects a certificate for SNI host "alpha.example.com"
        Then the selected certificate is the certificate for "route.alpha"
        And I renew "route.alpha" with a fresh certificate
        When Kestrel selects a certificate for SNI host "alpha.example.com"
        Then the selected certificate is the certificate for "route.alpha"
