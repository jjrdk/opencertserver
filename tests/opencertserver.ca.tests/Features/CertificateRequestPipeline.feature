Feature: Certificate request validation through the unified pipeline
    Existing request validators and context-based validators share the CA issuance path,
    including the caller, profile, re-enrollment source and cancellation token.

    Background:
        Given a CA with legacy and context-based request validators

    Scenario: The CA adapts existing request validators and invokes context-based validators
        When the CA signs through its request-validator constructor
        Then both request validator contracts ran with the complete enrollment context
        And the pipeline CA issued and stored the certificate

    Scenario: Legacy errors aggregate without skipping context-based validation
        Given the legacy request validator rejects the CSR
        When the CA signs through its request-validator constructor
        Then both request validator contracts ran with the complete enrollment context
        And the pipeline CA rejected without superseding the previous certificate

    Scenario: Registered request validators join the phased pipeline
        Given a pipeline validator in the "Data" phase returns "pass"
        And a pipeline validator in the "PreSign" phase returns "pass"
        And a pipeline validator in the "Post" phase returns "pass"
        When the CA signs through its registered-pipeline constructor
        Then the CA validation execution order is "Data, legacy, context, PreSign, Post"
        And the post validator inspected the signed certificate before persistence
        And the pipeline CA issued and stored the certificate

    Scenario: Both request validation contracts contribute their rejection reasons
        Given the legacy request validator rejects the CSR
        And the context-based request validator also rejects the CSR
        When the CA signs through its registered-pipeline constructor
        Then both request validator contracts ran with the complete enrollment context
        And the pipeline CA rejected without superseding the previous certificate
        And the pipeline CA refused issuance with "Context request rejected."

    Scenario: Early rejection prevents request validation and signing
        Given a pipeline validator in the "Data" phase returns "reject"
        And a pipeline validator in the "Post" phase returns "pass"
        When the CA signs through its registered-pipeline constructor
        Then the CA validation execution order is "Data"
        And the pipeline CA refused issuance with "Rejected by Data validator."

    Scenario: Pre-sign rejection prevents signing and the post hook
        Given a pipeline validator in the "PreSign" phase returns "reject"
        And a pipeline validator in the "Post" phase returns "pass"
        When the CA signs through its registered-pipeline constructor
        Then the CA validation execution order is "legacy, context, PreSign"
        And the pipeline CA refused issuance with "Rejected by PreSign validator."

    Scenario: A post-sign rejection prevents storage and supersession
        Given a pipeline validator in the "Post" phase returns "reject"
        When the CA signs through its registered-pipeline constructor
        Then the CA validation execution order is "legacy, context, Post"
        And the post validator inspected the signed certificate before persistence
        And the pipeline CA refused issuance with "Rejected by Post validator."

    Scenario Outline: An approval request cannot be treated as successful issuance
        Given a pipeline validator in the "<Phase>" phase returns "<Outcome>"
        When the CA signs through its registered-pipeline constructor
        Then the pipeline CA refused issuance with "<Error>"

        Examples:
            | Phase   | Outcome         | Error                                  |
            | PreSign | approval        | Certificate request requires approval. |
            | PreSign | custom approval | Certificate request requires approval. |
            | Post    | approval        | Issued certificate requires approval.  |

    Scenario: Cancellation stops validation without changing the certificate store
        When the CA signing operation is cancelled before validation
