Feature: Additional webhook authorization for Intune SCEP

    Intune generates the challenge and validates the CSR. A configured webhook
    provides an additional decision and cannot replace Intune's validation.

    Scenario: An Intune device enrolls when the webhook allows it
        Given an Intune SCEP server with a webhook that allows enrollment
        When a managed device enrolls through the webhook
        Then the dynamic enrollment succeeds
        And Intune and the webhook both validated the request
        And the device appears in the authorized certificate report

    Scenario: A webhook outage denies enrollment
        Given an Intune SCEP server with an unavailable webhook
        When a managed device enrolls through the webhook
        Then the dynamic enrollment fails
        And Intune receives a failure notification for the webhook denial

    Scenario: A webhook connection failure denies enrollment
        Given an Intune SCEP server with an unreachable webhook
        When a managed device enrolls through the webhook
        Then the dynamic enrollment fails
        And Intune receives a failure notification for the webhook denial

    Scenario: A malformed webhook response denies enrollment
        Given an Intune SCEP server with a malformed webhook response
        When a managed device enrolls through the webhook
        Then the dynamic enrollment fails
        And Intune receives a failure notification for the webhook denial

    Scenario: A webhook refusal denies enrollment
        Given an Intune SCEP server with a webhook that refuses enrollment
        When a managed device enrolls through the webhook
        Then the dynamic enrollment fails
        And Intune receives a failure notification for the webhook denial

    Scenario: A webhook response without a decision denies enrollment
        Given an Intune SCEP server with a webhook response without a decision
        When a managed device enrolls through the webhook
        Then the dynamic enrollment fails
        And Intune receives a failure notification for the webhook denial

    Scenario: Intune refuses before the webhook is called
        Given an Intune SCEP server with a webhook that allows enrollment
        And Intune refuses the dynamic enrollment
        When a managed device enrolls through the webhook
        Then the dynamic enrollment fails
        And the webhook was not called

    Scenario: The device report requires authorization
        Given an Intune SCEP server with a webhook that allows enrollment
        When the dynamic device report is requested anonymously
        Then the dynamic device report is unauthorized

    Scenario: An insecure webhook URL is rejected during registration
        Given a dynamic webhook configured with an insecure URL
        Then dynamic webhook registration is rejected
