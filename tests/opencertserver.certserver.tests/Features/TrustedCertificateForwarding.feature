@trusted-certificate-forwarding
Feature: Certificate forwarding requires an explicitly trusted TLS proxy
    Public certificate data cannot authenticate a direct connection.

    Scenario Outline: A genuine certificate header only authenticates an opted-in proxy
        Given certificate forwarding is "<mode>"
        When peer "<peer>" sends a genuine certificate header to "<endpoint>"
        Then the forwarded certificate request returns <status>

        Examples:
          | mode    | peer             | endpoint      | status |
          | default | 192.0.2.10       | simpleenroll  | 401    |
          | default | 192.0.2.10       | simplereenroll| 401    |
          | enabled | 192.0.2.10       | probe         | 200    |
          | enabled | ::ffff:192.0.2.10| probe         | 200    |
          | enabled | 198.51.100.20    | probe         | 401    |
          | network | 192.0.2.20       | probe         | 200    |
          | network | 198.51.100.20    | probe         | 401    |
          | custom  | 192.0.2.10       | probe         | 200    |
          | custom  | 198.51.100.20    | probe         | 401    |

    Scenario: A forged forwarded address cannot bypass the certificate proxy allow-list
        Given certificate forwarding is "enabled"
        When an untrusted peer forges a trusted forwarded address
        Then the forwarded certificate request returns 401

    Scenario: An untrusted certificate header does not replace the TLS client identity
        Given certificate forwarding is "enabled"
        When an untrusted peer sends a victim header with its own TLS certificate
        Then only the TLS certificate identity is authenticated

    Scenario Outline: Incomplete forwarding configuration fails at startup
        When certificate forwarding is enabled with "<configuration>"
        Then certificate forwarding configuration is rejected

        Examples:
          | configuration    |
          | missing header   |
          | missing proxies  |
          | invalid proxy    |
          | invalid network  |
          | invalid header   |
