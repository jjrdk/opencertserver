Feature: Multi-Perspective Issuance Corroboration

    CA/Browser Forum TLS Baseline Requirements §3.2.2.9 requires a CA to
    corroborate domain validation and CAA determinations from multiple Network
    Perspectives. OpenCertServer treats each configured DNS-over-HTTPS server
    as one perspective and rejects a challenge when any perspective fails or
    when their DNS responses differ.

    Rule: configured DoH servers become Network Perspectives

        Scenario: each configured DoH server is used as a separate perspective
            Given the DoH servers "Cloudflare,Google,https://dns.quad9.net/dns-query" are configured
            When the DNS perspectives are created from configuration
            Then there must be 3 distinct DNS perspectives

        Scenario: an empty DoH list falls back to the single configured endpoint
            Given no DoH servers are configured
            And the legacy DNS endpoint is "Google"
            When the DNS perspectives are created from configuration
            Then there must be 1 distinct DNS perspective

    Rule: dns-01 TXT lookups are corroborated

        Scenario: matching TXT records from every perspective validate the challenge
            Given an ACME account with a pending dns-01 challenge for "example.com"
            And the dns-01 perspectives return the expected TXT record
            When the dns-01 challenge is validated with multi-perspective DNS
            Then the corroborated challenge must succeed

        Scenario: differing TXT records invalidate the challenge
            Given an ACME account with a pending dns-01 challenge for "example.com"
            And the dns-01 perspectives return different TXT records
            When the dns-01 challenge is validated with multi-perspective DNS
            Then the corroborated challenge must fail with error type "dns"

        Scenario: an unavailable perspective invalidates the challenge
            Given an ACME account with a pending dns-01 challenge for "example.com"
            And one dns-01 perspective fails
            When the dns-01 challenge is validated with multi-perspective DNS
            Then the corroborated challenge must fail with error type "dns"

    Rule: http-01 IP lookups are corroborated

        Scenario: matching IP addresses from every perspective validate the challenge
            Given an ACME account with a pending http-01 challenge for "example.com"
            And the http-01 perspectives return the same IP address "93.184.216.34"
            And the challenge server returns the expected token
            When the http-01 challenge is validated with multi-perspective DNS
            Then the corroborated challenge must succeed

        Scenario: differing IP addresses invalidate the challenge
            Given an ACME account with a pending http-01 challenge for "example.com"
            And the http-01 perspectives return different IP addresses
            When the http-01 challenge is validated with multi-perspective DNS
            Then the corroborated challenge must fail with error type "dns"

    Rule: CAA lookups are corroborated

        Scenario: differing CAA records are rejected
            Given two perspectives return different CAA records
            When CAA is resolved with multi-perspective DNS
            Then the corroborated DNS lookup must fail with a perspective mismatch
