@iq @blackbox @linux-client
Feature: RFC 8894 SCEP enrollment works for a Linux device client
  Device management deploys certificates over SCEP: the device proves itself with a
  challenge password, encrypts its request to the registration authority and receives
  the certificate in a signed, encrypted reply. These scenarios use micromdm's
  `scepclient`, an independent SCEP implementation, against the running installation,
  and check what it receives with `openssl`.

  They complement the SCEP scenarios in-process; the new assertion is that a real SCEP
  client completes enrollment and renewal over TLS against the hardened server.

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
  Scenario: scepclient enrolls with the challenge and receives a usable certificate
    Given the hardened OpenCertServer is reachable over TLS
    When scepclient enrolls "scep-device" with the right challenge
    Then scepclient exits with code 0
    And the certificate names "scep-device" and chains to the published CA with "openssl verify"

  Scenario: A wrong challenge password is refused
    Given the hardened OpenCertServer is reachable over TLS
    When scepclient enrolls "scep-intruder" with the challenge "wrong-challenge"
    Then scepclient fails with a SCEP FAILURE
    And no certificate is written

  # Windows appends /pkiclient.exe to the SCEP server URL configured in Intune.
  Scenario: A client using the Windows path enrolls
    Given the hardened OpenCertServer is reachable over TLS
    When scepclient enrolls "scep-windows-path" with the right challenge at "/scep/pkiclient.exe"
    Then scepclient exits with code 0
    And the certificate names "scep-windows-path" and chains to the published CA with "openssl verify"

  Rule: A device renews with the certificate it holds
  Scenario: scepclient renews with a RenewalReq signed by its certificate
    Given scepclient holds a certificate for "scep-renewal"
    When scepclient runs again with that certificate
    Then scepclient exits with code 0
    And the renewed certificate has a new serial number and chains to the published CA
