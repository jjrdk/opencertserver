Feature: External account key file store contention

  Scenario: File operations wait for an exclusive holder
    Given a provisioned external account key in a file store
    Then all file store operations wait for an exclusive file holder

  Scenario: File sharing retries have a limit and support cancellation
    Given a provisioned external account key in a file store
    Then locked file retries are bounded and cancellation is honored

  Scenario: Concurrent store instances preserve versioning and single use
    Given a provisioned external account key in a file store
    Then concurrent stores preserve versioning and only one consumer wins
