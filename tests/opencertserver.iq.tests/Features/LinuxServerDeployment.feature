@iq @blackbox @linux-client @hardened
Feature: A deployed, hardened OpenCertServer is reachable and healthy over TLS from a Linux client
  A freshly started, hardened OpenCertServer installation (the "install") answers a
  Linux client the way a real deployment must: a reachable server on TLS 1.2/1.3,
  no Server header, an HTTP-to-HTTPS redirect, a health probe, and a published
  CA chain. This is the entry point for every other IQ feature: if the install is
  not reachable and hard, nothing else can be verified from the outside.

  The scenarios are driven from a Linux client container using `curl` and
  `openssl s_client`. They complement the protocol conformance suites (which reach
  the same endpoints in-process); here the new assertion is that the feature is
  *observable over the network from Linux*, under a hardened posture.

  Rule: The install answers a health probe
  Scenario: A running server exposes the health endpoint the deployment probes
    Given a hardened OpenCertServer is running and has passed its health check
    When the Linux client GETs "/health" over HTTPS with curl
    Then the response is HTTP 200
    And the response body reports a healthy server

  Rule: The server speaks only modern TLS
  Scenario Outline: The hardened server negotiates <protocol>
    Given a hardened OpenCertServer is running on <protocol>
    When the Linux client opens a <protocol> connection with "openssl s_client"
    Then the TLS handshake completes
    And the server presents an X.509 certificate that chains to a trusted root

    Examples:
      | protocol |
      | TLS 1.2  |
      | TLS 1.3  |

  Scenario Outline: The hardened server rejects <protocol>
    # RFC 7030 requires TLS 1.1+; the hardened install pins 1.2/1.3 and refuses anything older.
    Given a hardened OpenCertServer is running on TLS 1.2/1.3
    And the client tries to negotiate <protocol>
    When the Linux client attempts a <protocol> handshake with "openssl s_client"
    Then the connection is refused

    Examples:
      | protocol |
      | TLS 1.0  |
      | TLS 1.1  |

  Rule: The server hides its implementation and redirects plain HTTP
  Scenario: The hardened server does not advertise a Server header
    When the Linux client GETs the CA certificates with "curl -sS -D -"
    Then the response headers contain no "Server" field

  Scenario: The hardened server redirects HTTP to HTTPS
    When the Linux client GETs the health endpoint over plain HTTP with curl
    Then the response is an HTTP 3xx redirect to the HTTPS endpoint

  Rule: The published CA chain is reachable
  Scenario: The CA certificates are published for a Linux client
    When the Linux client GETs "/.well-known/est/cacerts" with curl
    Then the response content-type is "application/pkcs7-mime; smime-type=certs-only"
    And the response body decodes to a non-empty X.509 chain with "openssl"
