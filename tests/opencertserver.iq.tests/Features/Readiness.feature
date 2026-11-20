Feature: IQ readiness probes recover from transient timeouts

  Scenario: A stalled startup connection can be retried
    Given a readiness transport that stalls its first request
    When the stalled readiness attempt is retried
    Then the timeout is reported as a retryable HTTP failure
    And the next readiness attempt succeeds

  Scenario: A socket startup failure can be retried
    Given a readiness transport with a socket error on its first request
    When the socket readiness attempt is retried
    Then the socket error is reported as a retryable HTTP failure
    And the next readiness attempt succeeds

  Scenario: Caller cancellation is not treated as a startup timeout
    Given a readiness transport that stalls its first request
    When the caller cancels a readiness attempt
    Then caller cancellation is preserved

  Scenario Outline: Readiness transport does not replace HTTP status codes
    Given a readiness transport returning HTTP <Status>
    When the readiness response is received
    Then the readiness response still has HTTP <Status>

    Examples:
      | Status |
      | 200    |
      | 403    |
      | 503    |
