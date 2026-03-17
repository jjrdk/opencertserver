Feature: Create CSR non-interactive
  As an automation user
  I want to create a CSR non-interactively
  So that CI systems can generate CSRs without interactive prompts

  Scenario: Create CSR using non-interactive options and generated key
    When I run the CLI with "create-csr --private-key <GENERATE_KEY> --out <TEMP_OUT> --C US --ST CA --L SanFrancisco --O MyOrg --OU MyUnit --CN example.com --E admin@example.com --san example.com,127.0.0.1 --key-usage digitalSignature,keyEncipherment --eku serverAuth,clientAuth --basic-ca false"
    Then the output should contain "CSR written to"
    And the file "<TEMP_OUT>" should exist and contain CSR



