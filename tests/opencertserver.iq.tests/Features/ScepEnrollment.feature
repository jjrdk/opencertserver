@iq @blackbox @linux-client
Feature: RFC 8894 SCEP enrollment works for a Linux device client
  Device management deploys certificates over SCEP: the device proves itself with a
  challenge password, encrypts its request to the registration authority and receives
  the certificate in a signed, encrypted reply. These scenarios use `sscep`, an
  independent SCEP implementation in C, against the running installation, and check what
  it receives with `openssl`. sscep speaks plain HTTP; a `socat` bridge in the client
  carries it to the server over TLS and verifies the server certificate.

  The MicroMDM/smallstep client SDK additionally sends real RenewalReq messages and
  qualifies both HTTP transports and all default/named-profile endpoint forms directly
  over verified HTTPS. The SDK, not OpenCertServer code, builds and verifies SCEP messages.

  Rule: A device learns what the server offers
  Scenario: The Linux client reads the SCEP capabilities
    Given the hardened OpenCertServer is reachable over TLS
    When the Linux client asks for the SCEP capabilities
    Then the capabilities include POSTPKIOperation, SHA-256, AES and Renewal

  Scenario: The Linux client fetches the RA and CA certificates
    Given the hardened OpenCertServer is reachable over TLS
    When the Linux client fetches the SCEP CA certificates
    Then the bundle holds an RA certificate for key encipherment and a CA certificate

  Rule: A device enrolls with the challenge password
  Scenario: sscep enrolls with the challenge and receives a usable certificate
    Given the hardened OpenCertServer is reachable over TLS
    When sscep enrolls "scep-device" with the right challenge
    Then sscep exits with code 0
    And the certificate names "scep-device" and chains to the published CA with "openssl verify"

  Scenario: A wrong challenge password is refused
    Given the hardened OpenCertServer is reachable over TLS
    When sscep enrolls "scep-intruder" with the challenge "wrong-challenge"
    Then sscep fails with a SCEP FAILURE "badRequest"
    And no certificate is written

  # Windows appends /pkiclient.exe to the SCEP server URL configured in Intune.
  Scenario: A client using the Windows path enrolls
    Given the hardened OpenCertServer is reachable over TLS
    When sscep enrolls "scep-windows-path" with the right challenge at "/scep/pkiclient.exe"
    Then sscep exits with code 0
    And the certificate names "scep-windows-path" and chains to the published CA with "openssl verify"

  # The capabilities offer AES only; anything else is refused, not decrypted (RFC 8894, 3.2.1.4).
  Scenario: A request encrypted with triple DES is refused with badAlg
    Given the hardened OpenCertServer is reachable over TLS
    When sscep enrolls "scep-3des" with the right challenge and the request encrypted with "3des"
    Then sscep fails with a SCEP FAILURE "badAlg"
    And no certificate is written

  Rule: A device enrolls again with the certificate it holds
  # sscep has no RenewalReq: it re-enrolls with a PKCSReq that carries the challenge and is
  # signed with the certificate it holds. MicroMDM below qualifies actual RenewalReq.
  Scenario: sscep enrolls again, signing with the certificate it holds
    Given sscep holds a certificate for "scep-renewal"
    When sscep enrolls again with a new key, signing with that certificate
    Then sscep exits with code 0
    And the renewed certificate has a new serial number and chains to the published CA

  Rule: All endpoint forms support both transports with an independent client SDK
  Scenario Outline: MicroMDM enrolls and renews over <Method> at <Path>
    Given the hardened OpenCertServer is reachable over TLS
    When the MicroMDM client enrolls and renews "micromdm-device" over "<Method>" at "<Path>"
    Then the MicroMDM client verifies successful PKCSReq and RenewalReq replies
    And the certificate names "micromdm-device" and chains to the published CA with "openssl verify"
    And the certificate uses the issuing profile selected by the SCEP path
    And the renewed certificate has a different key and serial from the original certificate

    Examples:
      | Method | Path                       |
      | POST   | /scep                      |
      | GET    | /scep                      |
      | POST   | /scep/pkiclient.exe         |
      | GET    | /scep/pkiclient.exe         |
      | POST   | /scep/rsa                  |
      | GET    | /scep/rsa                  |
      | POST   | /scep/rsa/pkiclient.exe     |
      | GET    | /scep/rsa/pkiclient.exe     |
      | POST   | /scep/ecdsa                |
      | GET    | /scep/ecdsa                |
      | POST   | /scep/ecdsa/pkiclient.exe   |
      | GET    | /scep/ecdsa/pkiclient.exe   |

  Rule: Hardened refusals remain signed protocol replies, not transport errors
  Scenario Outline: MicroMDM cannot enroll without the configured challenge over <Method>
    Given the hardened OpenCertServer is reachable over TLS
    When the MicroMDM client enrolls without a challenge over "<Method>"
    Then the MicroMDM client verifies a signed PKCSReq badRequest refusal
    And no certificate is written

    Examples:
      | Method |
      | POST   |
      | GET    |

  Scenario Outline: MicroMDM cannot renew another subject over <Method>
    Given the hardened OpenCertServer is reachable over TLS
    When the MicroMDM client renews with a changed subject over "<Method>"
    Then the MicroMDM client verifies a signed RenewalReq badRequest refusal
    And no certificate is written

    Examples:
      | Method |
      | POST   |
      | GET    |

  Scenario Outline: MicroMDM cannot replay an accepted enrollment over <Method>
    Given the hardened OpenCertServer is reachable over TLS
    When the MicroMDM client replays an accepted enrollment over "<Method>"
    Then the MicroMDM client verifies a signed PKCSReq badRequest refusal
    And no certificate is written

    Examples:
      | Method |
      | POST   |
      | GET    |
