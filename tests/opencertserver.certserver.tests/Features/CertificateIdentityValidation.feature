@rfc9525 @validation
Feature: RFC 9525 Certificate Service Identity Validation
  As a TLS client library author
  I want to verify a server certificate's subjectAltName against the service I am trying to reach
  So that I prevent man-in-the-middle attacks per RFC 9525, which obsoletes RFC 6125.

  # RFC 9525 central rule: the identifier is carried ONLY in subjectAltName. There is no fallback to
  # the certificate subject / common name, which is the root of several historical MITM CVEs.
  # The acceptable reference identifiers are supplied by an injected IServiceProviderLookup; the
  # concrete lookup is intentionally out of scope, so a mocked lookup exercises the algorithm.

  Background:
    Given a service provider lookup

  # -- DNS identifier matching --------------------------------------------------------------

  Scenario Outline: A presented DNS name is matched case-insensitively against the reference
    Given the reference service is DNS name "<reference>"
    And the lookup resolves to DNS name "<resolved>"
    And the certificate presents DNS name "<presented>"
    When the certificate is validated for the reference service
    Then the result is a match for the reference service

    Examples:
      | reference       | resolved      | presented       |
      | web.example.com | web.example.com | web.example.com |
      | web.example.com | web.example.com | WEB.EXAMPLE.COM |

  Scenario: A left-most wildcard matches exactly one DNS label
    Given the reference service is DNS name "*.example.com"
    And the lookup resolves to DNS name "*.example.com"
    And the certificate presents DNS name "api.example.com"
    When the certificate is validated for the reference service
    Then the result is a match for the reference service

  Scenario: A wildcard does not match the apex domain
    Given the reference service is DNS name "*.example.com"
    And the lookup resolves to DNS name "*.example.com"
    And the certificate presents DNS name "example.com"
    When the certificate is validated for the reference service
    Then the result does not match

  Scenario: A wildcard does not match across more than one label
    Given the reference service is DNS name "*.example.com"
    And the lookup resolves to DNS name "*.example.com"
    And the certificate presents DNS name "api.sub.example.com"
    When the certificate is validated for the reference service
    Then the result does not match

  Scenario: A malformed presented wildcard is ignored
    Given the reference service is DNS name "www.example.com"
    And the lookup resolves to DNS name "www.example.com"
    And the certificate presents DNS name "a*.example.com"
    When the certificate is validated for the reference service
    Then the result does not match

  # -- No subjectAltName, no common-name fallback ------------------------------------------

  Scenario: A certificate without a subjectAltName fails even when the common name matches
    Given the reference service is DNS name "web.example.com"
    And the lookup resolves to DNS name "web.example.com"
    And the certificate has subject "CN=web.example.com"
    And the certificate presents no subject alternative names
    When the certificate is validated for the reference service
    Then the result fails with "missing subject alternative name"

  # -- Reference resolution ---------------------------------------------------------------

  Scenario: When the reference resolves to no identifiers the validation fails
    Given the reference service is DNS name "web.example.com"
    And the certificate presents DNS name "web.example.com"
    When the certificate is validated for the reference service
    Then the result fails with "no reference identities"

  Scenario: The service provider lookup is consulted with the reference service
    Given the reference service is DNS name "web.example.com"
    And the lookup resolves to DNS name "web.example.com"
    And the certificate presents DNS name "web.example.com"
    When the certificate is validated for the reference service
    Then the service provider lookup was consulted for the reference service
    And the result is a match for the reference service

  # -- IP identifier matching --------------------------------------------------------------

  Scenario: An IP address is matched octet-for-octet
    Given the reference service is IP address "192.0.2.107"
    And the lookup resolves to IP address "192.0.2.107"
    And the certificate presents IP address "192.0.2.107"
    When the certificate is validated for the reference service
    Then the result is a match for the reference service

  Scenario: A mismatched IP address does not match
    Given the reference service is IP address "192.0.2.107"
    And the lookup resolves to IP address "192.0.2.107"
    And the certificate presents IP address "192.0.2.108"
    When the certificate is validated for the reference service
    Then the result does not match

  Scenario: A DNS reference never matches an IP presentation
    Given the reference service is DNS name "web.example.com"
    And the lookup resolves to DNS name "web.example.com"
    And the certificate presents IP address "192.0.2.107"
    When the certificate is validated for the reference service
    Then the result fails with "no match"

  # -- URI identifier matching -------------------------------------------------------------

  Scenario Outline: A presented URI is matched by scheme and host
    Given the reference service is URI "<referenceUri>"
    And the lookup resolves to URI "<referenceUri>"
    And the certificate presents URI "<presentedUri>"
    When the certificate is validated for the reference service
    Then <outcome>

    Examples:
      | referenceUri             | presentedUri            | outcome                          |
      | sip:voice.example.com    | sip:voice.example.com   | the result is a match            |
      | sip:voice.example.com    | sip:voice.college.example | the result does not match      |

  # -- SRV identifier matching (exercised on the matcher directly) -------------------------

  Scenario: An SRV identifier is matched by service type and domain, case-insensitively
    Given the matcher compares SRV name "_imaps.isp.example" against the presented SRV name "_IMAPS.isp.EXAMPLE"
    Then the match is found

  Scenario: An SRV identifier with a different service type does not match
    Given the matcher compares SRV name "_imap.isp.example" against the presented SRV name "_imaps.isp.example"
    Then the match is not found

  # -- Argument validation ----------------------------------------------------------------

  Scenario: A null certificate is rejected
    Given the reference service is DNS name "web.example.com"
    And the certificate is absent
    When the certificate is validated for the reference service
    Then an argument exception is thrown

  Scenario: A null reference is rejected
    Given the certificate presents DNS name "web.example.com"
    When the certificate is validated for the absent reference service
    Then an argument exception is thrown
