@profile-trust-config
Feature: CA profile trust configuration
    Profile client authentication trust is independent of issuing CA publication.

    Scenario Outline: Profile trust settings load explicit roots and untrusted intermediates
        Given PEM files for an issuing chain and external client trust
        When a CA profile is loaded with "<shape>" trust settings
        Then the profile contains its issuing chain and separate external client trust
        And its published CA bundle contains the issuing chain and publication supplements only

        Examples:
          | shape  |
          | scalar |
          | array  |

    Scenario Outline: Invalid profile trust configuration fails closed
        Given PEM files for an issuing chain and external client trust
        When a CA profile is loaded with a "<invalid>" trust file
        Then profile trust configuration fails

        Examples:
          | invalid             |
          | missing             |
          | empty               |
          | non-CA              |
          | no certificate sign |

    Scenario: Invalid programmatic profile anchors are rejected
        Given PEM files for an issuing chain and external client trust
        Then a non-CA certificate cannot be configured as profile trust

    Scenario: Profile client trust survives rollover and closing the publication window
        Given PEM files for an issuing chain and external client trust
        When a CA profile is loaded with "scalar" trust settings
        Then its explicit client trust survives CA rollover and closing the publication window
