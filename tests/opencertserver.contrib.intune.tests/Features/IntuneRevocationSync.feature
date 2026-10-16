Feature: Revocation sync for Intune-issued certificates

    Intune never tells the CA when a user is disabled or a device is retired. The sync
    asks Microsoft Graph about every certificate's user and device and revokes what is
    gone. Graph unreachable or throttled means unknown, and unknown is never revoked.

    Background:
        Given a CA with a certificate for the user "anna@contoso.test"
        And a certificate for the user "bert@contoso.test" on the Intune device "11111111-1111-1111-1111-111111111111"
        And a device certificate for the Entra device "22222222-2222-2222-2222-222222222222"
        And a server certificate for "vpn.contoso.test"
        And the directory knows all of them as enabled

    Scenario: Everything is still there
        When the sync runs
        Then 3 certificates were checked
        And nothing was revoked

    Scenario: A disabled user loses the certificate
        Given the user "anna@contoso.test" is disabled
        When the sync runs
        Then the certificate for "anna@contoso.test" is revoked with "The user is disabled in Entra."
        And the certificate for "bert@contoso.test" is still valid

    Scenario: A deleted user loses the certificate
        Given the user "anna@contoso.test" is deleted
        When the sync runs
        Then the certificate for "anna@contoso.test" is revoked with "The user no longer exists in Entra."

    Scenario: A retired Intune device loses the certificate
        Given the Intune device "11111111-1111-1111-1111-111111111111" is retired
        When the sync runs
        Then the certificate for "bert@contoso.test" is revoked with "The device is no longer managed by Intune (retired, wiped or deleted)."
        And the certificate for "anna@contoso.test" is still valid

    Scenario: A disabled Entra device loses the device certificate
        Given the Entra device "22222222-2222-2222-2222-222222222222" is disabled
        When the sync runs
        Then the device certificate is revoked with "The device is disabled in Entra."

    Scenario: Graph throttles - nothing is revoked
        Given the user "anna@contoso.test" is disabled
        And Graph answers with HTTP 429
        When the sync runs
        Then nothing was revoked
        And 3 certificates are reported as unknown

    Scenario: Graph is unreachable - nothing is revoked
        Given the user "anna@contoso.test" is disabled
        And Graph is unreachable
        When the sync runs
        Then nothing was revoked
        And 3 certificates are reported as unknown

    Scenario: A dry run reports but revokes nothing
        Given the user "anna@contoso.test" is disabled
        When the sync runs as a dry run
        Then the report lists "anna@contoso.test" as to be revoked
        And the certificate for "anna@contoso.test" is still valid

    Scenario: Too many hits abort the run
        Given the user "anna@contoso.test" is disabled
        And the user "bert@contoso.test" is disabled
        And the sync may revoke at most 1 certificate per run
        When the sync runs
        Then the run was aborted
        And nothing was revoked

    Scenario: A second run while one is in progress is rejected
        Given Graph answers only when released
        When the sync is started
        And the sync runs
        Then the second run was rejected as already running
        And Graph is released

    Scenario: The sync endpoint requires its own policy
        When the sync endpoint is called without authentication
        Then the endpoint answers HTTP 401
        When the sync endpoint is called by the configured caller as a dry run
        Then the endpoint answers HTTP 200 with a report
