@iq @pentest @network
Feature: Certificate server perimeter security from a Linux scanner
  OpenSSL, Nmap, curl and raw Python TLS probes run in the Linux IQ client.
  The target is the real opencertserver.certserver executable in its own container.
  Every finding fails the scenario; tool errors and inconclusive scans never pass.

  Scenario: TLS-01 Reject TLS 1.0
    When the Linux scanner runs certificate server penetration probe "TLS-01"
    Then the certificate server security requirement is satisfied

  Scenario: TLS-02 Reject TLS 1.1
    When the Linux scanner runs certificate server penetration probe "TLS-02"
    Then the certificate server security requirement is satisfied

  Scenario: TLS-03 Support TLS 1.2 with a trusted server identity
    When the Linux scanner runs certificate server penetration probe "TLS-03"
    Then the certificate server security requirement is satisfied

  Scenario: TLS-04 Support TLS 1.3 with a trusted server identity
    When the Linux scanner runs certificate server penetration probe "TLS-04"
    Then the certificate server security requirement is satisfied

  Scenario: TLS-05 Reject static RSA CBC cipher suites
    When the Linux scanner runs certificate server penetration probe "TLS-05"
    Then the certificate server security requirement is satisfied

  Scenario: TLS-06 Enumerate and reject weak cipher suites with Nmap
    When the Linux scanner runs certificate server penetration probe "TLS-06"
    Then the certificate server security requirement is satisfied

  Scenario: HTTP-01 Upgrade HTTP without trusting forged forwarding headers
    When the Linux scanner runs certificate server penetration probe "HTTP-01"
    Then the certificate server security requirement is satisfied

  Scenario: HTTP-02 Enforce persistent transport security
    When the Linux scanner runs certificate server penetration probe "HTTP-02"
    Then the certificate server security requirement is satisfied

  Scenario: HTTP-03 Suppress implementation banners
    When the Linux scanner runs certificate server penetration probe "HTTP-03"
    Then the certificate server security requirement is satisfied

  Scenario: HTTP-04 Reject TRACE on CA EST and ACME endpoints
    When the Linux scanner runs certificate server penetration probe "HTTP-04"
    Then the certificate server security requirement is satisfied

  Scenario: HTTP-05 Protect issuance key generation and revocation from anonymous callers
    When the Linux scanner runs certificate server penetration probe "HTTP-05"
    Then the certificate server security requirement is satisfied

  Scenario: HTTP-06 Reject unrecognized Host values before serving or redirecting
    When the Linux scanner runs certificate server penetration probe "HTTP-06"
    Then the certificate server security requirement is satisfied

  Scenario: HTTP-07 Reject forged client certificate identity headers
    When the Linux scanner runs certificate server penetration probe "HTTP-07"
    Then the certificate server security requirement is satisfied

  Scenario: HTTP-08 Reject ambiguous request framing and appended requests
    When the Linux scanner runs certificate server penetration probe "HTTP-08"
    Then the certificate server security requirement is satisfied

  Scenario: HTTP-09 Reject scanner paths and configuration file disclosure
    When the Linux scanner runs certificate server penetration probe "HTTP-09"
    Then the certificate server security requirement is satisfied

  Scenario: HTTP-10 Bound request header size
    When the Linux scanner runs certificate server penetration probe "HTTP-10"
    Then the certificate server security requirement is satisfied
