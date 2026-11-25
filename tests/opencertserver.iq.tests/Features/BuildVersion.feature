Feature: Cake build version formatting

  Scenario Outline: Branch names determine the build version
    When the build version is formatted for branch "<Branch>", version "4.2.1", and distance 12
    Then the build version is "<BuildVersion>"

    Examples:
      | Branch          | BuildVersion         |
      | beta/preview    | preview-12           |
      | beta/2.0.0-rc   | 2.0.0-rc-12         |
      | master          | 4.2.1                |
      | tags/v4.2.1     | 4.2.1                |
      | feature/example | 4.2.1-example.12     |
      | betamax/example | 4.2.1-example.12     |
