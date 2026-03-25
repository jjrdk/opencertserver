Feature: Generate key pairs
  As an automation user
  I want to generate PEM-encoded key pairs from the CLI
  So that I can save reusable public and private key files

  Scenario: Generate an RSA key pair
    When I run the CLI with "generate-keys --algorithm rsa --private-key-out <TEMP_PRIVATE_KEY> --public-key-out <TEMP_PUBLIC_KEY>"
    Then the output should contain "Generated RSA-3072 key pair."
    And the generated "rsa" key files "<TEMP_PRIVATE_KEY>" and "<TEMP_PUBLIC_KEY>" should exist and match

  Scenario: Generate an ECDSA key pair
    When I run the CLI with "generate-keys --algorithm ecdsa --private-key-out <TEMP_PRIVATE_KEY> --public-key-out <TEMP_PUBLIC_KEY>"
    Then the output should contain "Generated ECDSA-nistP256 key pair."
    And the generated "ecdsa" key files "<TEMP_PRIVATE_KEY>" and "<TEMP_PUBLIC_KEY>" should exist and match

  Scenario: Generate an RSA key pair using a shared output path
    When I run the CLI with "generate-keys --algorithm rsa --out <TEMP_KEY_PREFIX>"
    Then the output should contain "Generated RSA-3072 key pair."
    And the generated "rsa" key files "<TEMP_PRIVATE_KEY>" and "<TEMP_PUBLIC_KEY>" should exist and match
