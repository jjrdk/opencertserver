@iq @blackbox @linux-client
Feature: RFC 7030 EST enrollment works for a Linux device client
  A machine that does not yet hold a certificate must be able to enroll for one over
  TLS. These scenarios use Cisco libest's `estclient`, built from Ubuntu's libest-utils
  sources with documented compatibility fixes, to prove that enrollment works from Linux and that
  the issued chain is a usable, verifiable certificate - the practical outcome a
  device cares about.

  They complement the RFC 7030 conformance suite (in-process); the new assertion is
  that a real EST client completes the EST flow against the running
  installation and obtains a certificate the device can verify with `openssl`.

  Rule: A device obtains its CA chain
  Scenario: The Linux EST client fetches the server's CA certificates
    Given the hardened OpenCertServer is reachable over TLS
    When the Linux client fetches the server's CA certificates with "estclient -g"
    Then the EST client commands return exit code 0
    And the CA chain written to disk verifies with "openssl verify"

  Rule: A device enrolls without holding a certificate
  Scenario: EST enrollment returns a usable leaf certificate
    Given a hardened OpenCertServer authenticated with a JWT
    When the Linux client enrolls a leaf for "est.example.com" with "estclient -e"
    Then the EST client commands return exit code 0
    And the issued file is a valid X509 leaf decodable by "openssl x509"
    And the leaf chains to the published CA with "openssl verify"

  Scenario: A device re-enrolls using the certificate it just received
    Given a Linux device enrolls and holds a valid leaf certificate
    When the Linux client re-enrolls with "estclient -r" presenting that leaf over mTLS
    Then the EST client commands return exit code 0
    And the re-enrolled leaf chains to the published CA

  Rule: RFC 9908 hands the client a CSR template
  Scenario: The server advertises a CsrAttributesResponse a client must fill in
    Given the hardened OpenCertServer is reachable over TLS
    When the Linux client retrieves CSR attributes with "estclient -a"
    Then the EST client commands return exit code 0
    And the body is a CsrAttributesResponse naming the template the client must use

  Rule: Server-generated key delivery (§4.4)
  # libest 3.2.0 supports PKCS#8 delivery, not encrypted CMS AsymmetricKeyPackage.
  # Encrypted delivery remains covered by the EST conformance suite.
  Scenario: Server-keygen returns a usable RSA private key and certificate
    Given a hardened OpenCertServer authenticated with a JWT
    When the Linux client requests server-keygen with "estclient -q"
    Then the EST client commands return exit code 0
    And estclient writes a PKCS#8 RSA key matching the issued certificate

  Rule: HTTP Basic authentication (§3.2.3) over TLS
  Scenario: A user name and password authorize enrollment over TLS
    Given a hardened OpenCertServer is configured with an EST Basic user
    When the Linux client enrolls with "estclient -e -u <user> -h <password> --pem-output"
    Then the EST client commands return exit code 0
    And estclient writes a verifiable PEM leaf certificate
