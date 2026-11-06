Feature: http-01 challenge SSRF protection

The http-01 challenge validator must prevent Server-Side Request Forgery (SSRF)
and DNS-rebinding attacks by:
- rejecting connections whose resolved IP falls in a prohibited address range,
- using the configured resolver (DoH) for issuance-critical DNS lookups (F-07),
- pinning the HTTP connection to the corroborated address set instead of re-resolving, and
- not following HTTP redirects (prevents redirect-to-internal bypass).

Background:
    Given a valid ACME account with a pending http-01 challenge for "example.com"

Rule: connections to prohibited IP address ranges are rejected

Scenario Outline: challenge target resolving to a prohibited IP is rejected
    Given the DNS resolver returns the address "<ip>" for the challenge host
    When the http-01 challenge is validated
    Then the challenge must fail with error type "rejectedIdentifier"

Examples:
    | ip              |
    | 127.0.0.1       |
    | ::1             |
    | 10.0.0.1        |
    | 172.16.0.1      |
    | 192.168.1.1     |
    | 169.254.169.254 |
    | 169.254.1.1     |
    | 100.64.0.1      |

Rule: the configured resolver is used for IP address lookup

Scenario: http-01 validation queries the injected DNS resolver for IP addresses
    Given the DNS resolver returns the address "93.184.216.34" for the challenge host
    And the challenge server returns status 200 with the expected token
    When the http-01 challenge is validated
    Then the configured DNS resolver must have been queried for IP addresses
    And the challenge must succeed

Rule: the HTTP connection is pinned to the corroborated address set

Scenario: the challenge request carries the corroborated addresses
    Given the DNS resolver returns the address "93.184.216.34" for the challenge host
    And the challenge server returns status 200 with the expected token
    When the http-01 challenge is validated
    Then the challenge request must be pinned to the corroborated address "93.184.216.34"
    And the challenge must succeed

Scenario Outline: a pinned address in a prohibited range is still rejected at connection time
    Given the pinned connection addresses are "<ip>"
    When the connection target is selected
    Then the connection must be rejected as prohibited

Examples:
    | ip              |
    | 127.0.0.1       |
    | ::1             |
    | 10.0.0.1        |
    | 172.16.0.1      |
    | 192.168.1.1     |
    | 169.254.169.254 |
    | 100.64.0.1      |

Scenario: a pinned public address is selected without consulting ambient DNS
    Given the pinned connection addresses are "127.0.0.1,93.184.216.34"
    When the connection target is selected
    Then the selected connection target must be "93.184.216.34"

Rule: HTTP redirects are not followed

Scenario: a redirect from the challenge server is returned as an error not followed
    Given the DNS resolver returns the address "93.184.216.34" for the challenge host
    And the challenge server returns a 302 redirect
    When the http-01 challenge is validated
    Then the challenge must fail with error type "incorrectResponse"

Scenario: the production connection handler disables automatic redirects
    When the production HTTP handler is created
    Then automatic redirects must be disabled

Scenario: the production connection handler does not reuse pooled connections
    When the production HTTP handler is created
    Then pooled connections must not be reused

