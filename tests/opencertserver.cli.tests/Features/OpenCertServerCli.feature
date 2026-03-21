Feature: OpenCertServer CLI
  As a user of the OpenCertServer CLI
  I want to run certificate commands from the command line
  So that I can automate certificate operations

  Scenario: Print certificate details
    When I run the CLI with "print-cert --cert test.crt"
    Then the output should contain "Certificate:"

  Scenario: Sign a CSR
    When I run the CLI with "sign-csr --csr test.csr --ca-key ca.key --ca-cert ca.crt --out signed.crt"
    Then the certificate "signed.crt" should exist

