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

  Scenario: EST enrollment succeeds against the test server
    Given an EST server
    When I run the CLI with "est-enroll --url https://test --private-key <GENERATE_KEY> --out <TEMP_OUT> --C US --ST WA --L Redmond --O OpenCertServer --OU CLI --CN est.example.com --E admin@example.com --san est.example.com --key-usage digitalSignature --eku serverAuth"
    Then the certificate "<TEMP_OUT>" should exist

  Scenario: EST re-enrollment succeeds when the server is available
    Given an EST server
    When I run the CLI with "est-enroll --url https://test --private-key <GENERATE_KEY> --out <TEMP_OUT> --C US --ST WA --L Redmond --O OpenCertServer --OU CLI --CN est.example.com --E admin@example.com --san est.example.com --key-usage digitalSignature --eku serverAuth"
    When I run the CLI with "est-reenroll --url https://test --private-key <GENERATE_KEY> --cert <TEMP_OUT> --out <TEMP_REENROLL_OUT>"
    Then the certificate "<TEMP_REENROLL_OUT>" should exist

  Scenario: Fetch EST server certificates
    Given an EST server
    When I run the CLI with "est-server-certificates --url https://test"
    Then the output should contain "-----BEGIN CERTIFICATE-----"

