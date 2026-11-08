Feature: SCEP composition gate
    The SCEP surface is a per-host concern. A monolith enables it by default, so a fresh
    monolith maps /scep exactly as before, but a CA-only host can disable it and run /ca/*,
    /est and /acme with no SCEP endpoint. The gate is the decision that both registers the SCEP
    services and maps the SCEP routes, so a disabled host has neither.

    Scenario: A monolith enables SCEP by default
        Given a host with no SCEP configuration
        When the host decides whether to map SCEP
        Then SCEP is mapped

    Scenario: A configured SCEP challenge enables SCEP
        Given a host with a SCEP challenge "geheim"
        When the host decides whether to map SCEP
        Then SCEP is mapped

    Scenario: Intune validation enables SCEP
        Given a host with Intune SCEP validation
        When the host decides whether to map SCEP
        Then SCEP is mapped

    Scenario: A CA-only host disables SCEP
        Given a CA-only host that disables SCEP
        When the host decides whether to map SCEP
        Then SCEP is not mapped

    Scenario: A disabled SCEP surface stays off even with a challenge
        Given a host that disables SCEP but also configures a challenge "geheim"
        When the host decides whether to map SCEP
        Then SCEP is not mapped
