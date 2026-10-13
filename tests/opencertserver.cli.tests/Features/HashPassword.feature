Feature: Hash a password for EST Basic authentication
  The hash goes into Est:BasicAuth:Users; the password is read from standard input,
  never from the command line, where it would show in the process list.

  Scenario: Hash a password read from standard input
    When I run the CLI with "hash-password --iterations 10000" and "a long passphrase" on standard input
    Then the output should be a password hash that verifies "a long passphrase" and refuses "a long passphrasE"

  Scenario: Without a password on standard input nothing is hashed
    When I run the CLI with "hash-password" and "" on standard input
    Then the output should contain "No password on standard input."
