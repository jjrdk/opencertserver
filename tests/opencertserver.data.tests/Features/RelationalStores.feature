Feature: Relational ACME and CA stores
  Each examples table selects PostgreSQL or MSSQL to exercise the same store contracts.

  Scenario Outline: Accounts survive reloads and reject lost updates
    Given the relational database is "<Database>"
    Then accounts round trip and support contact updates and key rollover
    And concurrent account updates reject stale versions
    Examples:
      | Database   |
      | PostgreSQL |
      | MSSQL      |

  Scenario Outline: Orders preserve the full graph and validation lifecycle
    Given the relational database is "<Database>"
    Then orders preserve identities and parent references after reload
    And only orders with processing challenges are validatable
    And order updates preserve issuance data and reject stale versions
    Examples:
      | Database   |
      | PostgreSQL |
      | MSSQL      |

  Scenario Outline: Nonces are case sensitive and consumed atomically
    Given the relational database is "<Database>"
    Then concurrent nonce consumers have exactly one winner
    And nonce tokens are case sensitive
    And cancelled store operations propagate cancellation
    Examples:
      | Database   |
      | PostgreSQL |
      | MSSQL      |

  Scenario Outline: External account keys can be consumed only once across instances
    Given the relational database is "<Database>"
    Then external account keys preserve binding metadata across reloads
    And stale external account key consumers cannot overwrite the binding
    Examples:
      | Database   |
      | PostgreSQL |
      | MSSQL      |

  Scenario Outline: Certificate inventory and revocations match the memory store
    Given the relational database is "<Database>"
    Then certificate lookup and OCSP status survive reloads
    And paginated inventory and revocations match the memory store
    Examples:
      | Database   |
      | PostgreSQL |
      | MSSQL      |

  Scenario Outline: Migrations can be reapplied without losing data
    Given the relational database is "<Database>"
    Then applying the migrations again preserves stored accounts
    Examples:
      | Database   |
      | PostgreSQL |
      | MSSQL      |

  Scenario Outline: Relational store telemetry excludes sensitive values
    Given the relational database is "<Database>"
    Then nonce telemetry contains only fixed operation metadata
    Examples:
      | Database   |
      | PostgreSQL |
      | MSSQL      |

  Scenario: Persistence is opt in and configuration fails closed
    Then omitting relational registration preserves the existing stores
    And explicit relational registration uses the named standard connection regardless of persistence settings
    And invalid relational configuration is rejected
    And migration tooling reads named standard connection strings

  Scenario: Shared persistence is independent of database engines
    Then the shared data assembly has no database engine dependency
    And relational registration requires an explicit provider
    And database-specific operations use the injected provider
