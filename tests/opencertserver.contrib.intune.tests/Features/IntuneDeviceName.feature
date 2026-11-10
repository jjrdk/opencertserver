Feature: Device names for the certificate inventory

    A certificate names the Intune device by its id. An inventory page wants the name
    Intune shows for it - asked live, so a renamed device shows its new name.

    Scenario: A managed device has a name
        Given the Intune device "11111111-1111-1111-1111-111111111111" is called "RDK-001"
        When the name of the Intune device "11111111-1111-1111-1111-111111111111" is asked
        Then the name is "RDK-001"

    Scenario: A retired device has no name
        When the name of the Intune device "33333333-3333-3333-3333-333333333333" is asked
        Then there is no name

    Scenario: Graph throttled means the name is unknown, not missing
        Given the Intune device "11111111-1111-1111-1111-111111111111" is called "RDK-001"
        And Graph answers with HTTP 429 for device names
        When the name of the Intune device "11111111-1111-1111-1111-111111111111" is asked
        Then the lookup reports Graph as unavailable
