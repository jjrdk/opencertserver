Feature: http-01 challenge SSRF protection

The http-01 challenge validator must prevent Server-Side Request Forgery (SSRF)
and DNS-rebinding attacks by:
- rejecting connections whose resolved IP falls in a prohibited address range,
- using the configured resolver (DoH) for issuance-critical DNS lookups (F-07), and
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

Rule: HTTP redirects are not followed

Scenario: a redirect from the challenge server is returned as an error not followed
    Given the DNS resolver returns the address "93.184.216.34" for the challenge host
    And the challenge server returns a 302 redirect
    When the http-01 challenge is validated
    Then the challenge must fail with error type "incorrectResponse"

