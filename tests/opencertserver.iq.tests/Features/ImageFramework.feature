Feature: IQ images target the test assembly framework

  Scenario: Image publishes follow the framework the IQ tests were compiled for
    Then the IQ image target matches the compiled test assembly framework

  Scenario Outline: Generated image tags isolate frameworks and test runs
    Then the IQ "<Image>" image tag includes the compiled framework and the test run identity
    And the IQ publish artifacts are isolated to the test run

    Examples:
      | Image                     |
      | server                    |
      | client                    |
      | appliance-unified         |
      | appliance-ca-postgres     |
      | appliance-ra-mssql        |
