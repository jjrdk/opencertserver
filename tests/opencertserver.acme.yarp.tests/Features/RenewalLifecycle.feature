Feature: Per-route renewal lifecycle

    As the renewal service
    I want to renew every ACME route on its own schedule
    So that one failed route never blocks the others

    Scenario: Initial issuance on service start
        Given the ACME route "route.alpha" for host "alpha.example.com"
        And the ACME route "route.beta" for host "beta.example.com"
        When the renewal service runs its initial issuance
        Then the certificate for "route.alpha" is for host "alpha.example.com"
        And the certificate for "route.beta" is for host "beta.example.com"
        And no route failed during issuance
        And the lifecycle hook observed at least one start

    Scenario: A renewal failure of one route does not block the others
        Given the ACME route "route.alpha" for host "alpha.example.com"
        And the ACME route "route.beta" for host "beta.example.com"
        And the route "route.alpha" already has an issued certificate
        And renewing "route.alpha" throws
        When the renewal service runs a single pass for all routes
        Then the certificate for "route.alpha" is unchanged
        And the certificate for "route.beta" is changed
        And the lifecycle hook observed at least one exception

    Scenario: A stopped service halts all renewals
        Given the ACME route "route.alpha" for host "alpha.example.com"
        When the renewal service runs its initial issuance
        And the renewal service is stopped
        Then the lifecycle hook observed at least one start
        And the lifecycle hook observed at least one stop
