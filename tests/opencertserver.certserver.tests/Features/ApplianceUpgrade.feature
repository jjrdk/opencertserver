@appliance
Feature: Hardened appliance configuration and upgrades
  Operators run headless containers with read-only configuration and persistent state.

  Scenario: The hardened server starts from a mounted file and enforces TLS 1.3
    Given a hardened CA appliance configuration file
    When the appliance starts without certificate command line arguments
    Then the appliance health endpoint accepts TLS 1.3
    And the appliance rejects TLS 1.2
    And the CA-only appliance does not expose EST or ACME

  Scenario: The RA starts without issuing keys and protects its operator API
    Given a hardened RA appliance configuration file
    When the appliance starts without certificate command line arguments
    Then the appliance health endpoint accepts TLS 1.3
    And the appliance rejects TLS 1.2
    And the CA-only appliance does not expose EST or ACME
    And the RA requires an authenticated operator

  Scenario: The unified appliance exposes CA, EST and ACME from a mounted file
    Given a hardened unified appliance configuration file
    When the appliance starts without certificate command line arguments
    Then the appliance health endpoint accepts TLS 1.3
    And the appliance rejects TLS 1.2
    And the unified appliance exposes CA, EST and ACME
    And external-account-bound ACME state survives store reloads

  Scenario: ACME file persistence restores aggregate identity and challenge state
    Then the appliance ACME file store round-trips account and order aggregates
    And a persisted ACME nonce can only be consumed once concurrently
    And configured external account key consumption survives a store reload

  Scenario: An operator enrolls and revokes through the RA container and remote CA
    Given a hardened CA and RA container topology
    When an authorized RA operator enrolls an in-scope certificate
    Then the certificate is signed by the remote CA
    And the remote CA rejects an out-of-scope operator enrollment
    And the RA rejects malformed operator requests
    And the RA operator revokes the in-scope certificate

  Scenario: A migration upgrades a prior configuration store
    Given a version 1 appliance configuration store
    When the configuration is loaded into a new versioned store
    Then the store has version 2 and grouped JWT settings
    And configdump and configload round-trip the upgraded store

  Scenario: Read-only startup migration requires explicit consent
    Given a version 1 appliance configuration store
    Then startup rejects the old store without automatic migrations
    And automatic migration does not rewrite the mounted file

  Scenario: Future configuration versions fail closed
    Then an unsupported appliance configuration version is rejected

  Scenario: Hardened settings cannot disable CAA enforcement
    Then a hardened appliance rejects disabled CAA checks

  Scenario: Certificate inventory and revocations survive a restart
    Given a persistent appliance certificate store
    When a certificate is issued and revoked in the store
    Then the reopened store retains the certificate and revocation
