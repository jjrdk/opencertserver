Feature: Create CSR from key pair
  As an automation user
  I want to create a CSR using existing public/private key files
  So that pre-generated key pairs can be re-used without interactive prompts

  Scenario: Create CSR from matching key files
    When I run the CLI with "create-csr-from-keys --private-key ca.key --public-key ca.crt --out <TEMP_OUT> --C US --ST WA --L Redmond --O OpenCertServer --OU CLI --CN cli.example.com --E admin@example.com --san cli.example.com,127.0.0.1 --key-usage digitalSignature --eku serverAuth"
    Then the file "<TEMP_OUT>" should exist and contain CSR



