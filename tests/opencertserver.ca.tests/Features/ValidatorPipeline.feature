Feature: Phased validator pipeline (T09)
    The certificate authority runs validators in a fixed, phased order:
    Approval, Data, Issuance, PreSign, then Post on the signed certificate. A validator may pass, reject
    (optionally short-circuiting), or annotate the request (for example a "needs-approval" tag that T04 turns into
    a human-approval gate). The pre-sign phases gate issuance; the Post phase runs after signing.

    Background:
        Given a certificate request that is otherwise valid

    Scenario: Validators run in the fixed phase order
        Given a validator in the "Approval" phase that passes
        And a validator in the "Data" phase that passes
        And a validator in the "Issuance" phase that passes
        And a validator in the "PreSign" phase that passes
        When the pipeline runs the request
        Then the validators ran in the order "Approval, Data, Issuance, PreSign"
        And the pipeline approved the request

    Scenario: A Data-phase rejection prevents later-phase validators from running
        Given a validator in the "Approval" phase that passes
        And a validator in the "Data" phase that rejects
        And a validator in the "Issuance" phase that passes
        And a validator in the "PreSign" phase that passes
        When the pipeline runs the request
        Then the pipeline rejected the request
        And the validator in the "Issuance" phase did not run
        And the validator in the "PreSign" phase did not run

    Scenario: A short-circuiting validator stops the pipeline
        Given a validator in the "Approval" phase that rejects and short-circuits
        And a validator in the "Data" phase that passes
        And a validator in the "Issuance" phase that passes
        When the pipeline runs the request
        Then the pipeline rejected the request
        And the validator in the "Data" phase did not run
        And the validator in the "Issuance" phase did not run

    Scenario: A non-short-circuiting rejection is recorded and the pipeline continues
        Given a validator in the "Approval" phase that rejects without short-circuiting
        And a validator in the "Data" phase that passes
        When the pipeline runs the request
        Then the pipeline rejected the request
        And the validator in the "Data" phase did run

    Scenario: A validator can annotate the request without blocking it
        Given a validator in the "Data" phase that annotates the request with "needs-approval"
        And a validator in the "Issuance" phase that passes
        When the pipeline runs the request
        Then the pipeline requires approval
        And the request is annotated with "needs-approval"
        And the validator in the "Issuance" phase did run

    Scenario: When every validator passes the request is approved
        Given a validator in the "Approval" phase that passes
        And a validator in the "Issuance" phase that passes
        When the pipeline runs the request
        Then the pipeline approved the request
        And the request is not annotated

    Scenario: The Post phase runs on the signed certificate
        Given a validator in the "Issuance" phase that passes
        And a validator in the "Post" phase that passes
        When the pipeline runs the request
        And the pipeline runs the post-issue phase with the signed certificate
        Then the validator in the "Post" phase ran with the issued certificate
