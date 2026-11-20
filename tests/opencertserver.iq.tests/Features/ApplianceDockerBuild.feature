Feature: Appliance Docker build configuration

  Scenario Outline: Appliance images use matching publish and runtime frameworks
    Given the appliance build targets "<Framework>"
    Then each appliance role is published for that framework with its matching globalization setting
    And each appliance image uses matching build arguments and framework-qualified tags

    Examples:
      | Framework |
      | net10.0   |
      | net11.0   |
