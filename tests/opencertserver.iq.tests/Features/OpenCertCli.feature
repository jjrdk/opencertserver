@iq @blackbox @linux-client @hardened
Feature: The opencert CLI runs as a Linux binary that drives the server
  The `opencert` CLI is OpenCertServer's own command-line toolkit, packaged as a binary
  and installed in the Linux client image. These scenarios verify the CLI runs as a
  native Linux executable and can both perform offline PKI work and drive the remote
  server over the network - the automation path an operator uses on a host.

  They complement the CLI unit tests (which run in process); the new assertion is that
  the binary, *run inside the Linux client container*, does the job an operator expects.

  Rule: Offline PKI work
  Scenario: The CLI hashes a password to a PBKDF2 token
    When the Linux client runs "opencert hash-password" with a password
    Then the output is a PBKDF2-SHA256 hash

  Scenario: The CLI builds a key and a CSR
    When the Linux client runs "opencert generate-keys" then "opencert create-csr"
    Then a key file and a PKCS#10 CSR are produced
    And the CSR is verifiable with "openssl req -verify"

  Scenario: The CLI prints certificate details
    Given a certificate file on the Linux client
    When the Linux client runs "opencert print-cert" on it
    Then the output contains the certificate's subject and validity

  Rule: The CLI drives the remote server
  Scenario: est-enroll against the running server returns a certificate
    Given a hardened OpenCertServer reached by the Linux client
    When the Linux client runs "opencert est-enroll" with "opencert"-generated keys against the server
    Then opencert exits 0 and writes a certificate to disk

  Scenario: est-server-certificates prints the CA chain
    Given a hardened OpenCertServer reached by the Linux client
    When the Linux client runs "opencert est-server-certificates"
    Then the output contains "-----BEGIN CERTIFICATE-----"

  Scenario: est-reenroll renews the certificate the client holds
    Given a Linux client holding a certificate obtained by "opencert est-enroll"
    When the Linux client runs "opencert est-reenroll" with that certificate
    Then opencert exits 0 and writes a renewed certificate to disk
