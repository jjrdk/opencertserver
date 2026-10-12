@caa-enforcement
Feature: CAA enforcement fail-closed and explicit opt-out

    CAA checks must never silently fail-open. An ACME server with no configured
    CAAIdentities must reject every order unless the operator has explicitly
    set DisableCaaChecks to true to opt out of enforcement.

    Rule: empty CAAIdentities fails closed by default

        Scenario: issuance is rejected when CAAIdentities is not configured
            Given CAA identities are not configured
            When CAA validation runs for "example.com" with no records
            Then the CAA validation must reject issuance

        Scenario: issuance is rejected even when DNS has no CAA records and CAAIdentities is not configured
            Given CAA identities are not configured
            And there are no CAA records in DNS for "example.com"
            When CAA validation runs for "example.com" with no records
            Then the CAA validation must reject issuance

    Rule: DisableCaaChecks allows explicit opt-out

        Scenario: issuance is allowed when CAA checks are explicitly disabled
            Given CAA identities are not configured
            And CAA checks are explicitly disabled
            When CAA validation runs for "example.com" with no records
            Then the CAA validation must authorize issuance

        Scenario: DisableCaaChecks bypasses CAA DNS records even if CAAIdentities are set
            Given the CAA identity is "ca.example.com"
            And CAA checks are explicitly disabled
            When CAA validation runs for "example.com" with no records
            Then the CAA validation must authorize issuance
