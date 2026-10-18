@iq @blackbox @linux-client
Feature: OpenTelemetry signals are actually emitted after real traffic
  A deployable OpenCertServer must export metrics (and traces) under its
  `opencertserver.<protocol>.<operation>.<type>` namespace. These scenarios verify the
  *observable* telemetry a deployment pipeline would consume: that a Linux client driving
  the endpoints produces the expected counters and activity, not merely that the
  instruments exist in code.

  They complement the OpenTelemetry metric suite; the new assertion is that telemetry is
  *emitted for real, client-driven traffic* and is scrapeable/exportable.

  Rule: Endpoints produce counters
  Scenario: EST and OCSP endpoints increment counters
    Given a hardened OpenCertServer with OpenTelemetry metrics exported
    When the Linux client calls "/.well-known/est/cacerts" and a live OCSP status
    When that OpenTelemetry exporter is scraped
    Then the "opencertserver.est.cacerts" counter is greater than 0
    And the "opencertserver.ocsp" counter is greater than 0

  Rule: Success and failure outcomes are captured
  Scenario: A successful and a failed enrollment are both counted
    Given a hardened OpenCertServer with OpenTelemetry metrics exported
    When the Linux client performs one successful and one failing "simpleenroll"
    And the exporter is scraped
    Then a success outcome and a failure outcome are both reported for simpleenroll

  Rule: Traces are emitted across an operation
  Scenario: An enrollment produces a trace
    Given a hardened OpenCertServer with OpenTelemetry traces exported
    When the Linux client performs an EST enrollment
    Then an activity ("operation") was emitted for the enrollment
