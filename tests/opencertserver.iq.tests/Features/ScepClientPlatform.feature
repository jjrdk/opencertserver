@iq
Feature: SCEP clients target Docker independently of the test host
  macOS, Linux and Windows hosts run the external SCEP clients in Linux containers.
  Client images and published binaries must target the Docker daemon architecture,
  not the test runner architecture, including when Docker runs remotely.

  Scenario Outline: SCEP clients select the Docker platform rather than the host platform
    Given Docker reports operating system "<OS>" and architecture "<Architecture>"
    And the IQ Docker architecture override is "<Override>"
    When the IQ client platform is selected
    Then the IQ binaries target architecture "<BinaryArchitecture>" and the client image targets "<Platform>"

    Examples:
      | OS    | Architecture | Override | BinaryArchitecture | Platform    |
      | linux | amd64        |          | x64                | linux/amd64 |
      | linux | x86_64       |          | x64                | linux/amd64 |
      | linux | arm64        |          | arm64              | linux/arm64 |
      | linux | aarch64      |          | arm64              | linux/arm64 |
      | linux | arm64        | x64      | x64                | linux/amd64 |
      | linux | amd64        | arm64    | arm64              | linux/arm64 |

  Scenario Outline: An incompatible client environment fails with an actionable error
    Given Docker reports operating system "<OS>" and architecture "<Architecture>"
    And the IQ Docker architecture override is "<Override>"
    When the IQ client platform is selected
    Then client platform selection fails with "<Error>"

    Examples:
      | OS      | Architecture | Override | Error                                                |
      | windows | amd64        |          | switch Docker Desktop to Linux containers            |
      | linux   | armv7l       |          | Unsupported IQ Docker architecture 'armv7l'          |
      | linux   | amd64        | amd64    | IQ_DOCKER_ARCH must be 'x64' or 'arm64', got 'amd64'   |
      | linux   | arm64        | invalid  | IQ_DOCKER_ARCH must be 'x64' or 'arm64', got 'invalid' |
