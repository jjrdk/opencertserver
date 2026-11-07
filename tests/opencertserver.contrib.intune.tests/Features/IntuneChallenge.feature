Feature: SCEP enrollment validated by Intune

    Intune hands every device a challenge and checks it on request. The CA sends the
    whole request to Intune's validation service and issues only when Intune says yes.
    Intune unreachable, throttled or refusing all mean: nothing is issued.

    Scenario: Intune allows the request
        Given a SCEP server that asks Intune about every request
        When a device enrolls with the challenge Intune handed out
        Then the server answers SUCCESS
        And Intune was asked with the transaction id and the request
        And Intune received the success notification with thumbprint and serial number

    Scenario: Intune challenge validation emits metrics and a tag-free trace
        Given a SCEP server that asks Intune about every request
        And an Intune challenge OpenTelemetry listener
        When a device enrolls with the challenge Intune handed out
        Then Intune challenge telemetry is recorded without attributes

    Scenario: Intune refuses the request
        Given a SCEP server that asks Intune about every request
        And Intune refuses with "ChallengeExpired"
        When a device enrolls with the challenge Intune handed out
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned
        And Intune received no failure notification

    Scenario: Intune cannot be reached
        Given a SCEP server that asks Intune about every request
        And Intune is unreachable
        When a device enrolls with the challenge Intune handed out
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    # A renewal or a retry with the same key carries the earlier transaction ID: the
    # server accepts it as a new request, and each keeps its own state with Intune.
    Scenario: Two requests under one transaction ID keep their own state
        Given a SCEP server that asks Intune about every request
        When two requests under one transaction ID overlap, the first refused by the CA and the second issued
        Then Intune received one failure notification and one success notification

    # Discovery of the validation service goes through Graph; when that fails, the device
    # gets a SCEP FAILURE like for any other way Intune cannot be asked - not an HTTP 500.
    Scenario: The validation service cannot be discovered
        Given a SCEP server that asks Intune about every request
        And no token for Microsoft Graph can be obtained
        When a device enrolls with the challenge Intune handed out
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    Scenario: Intune throttles
        Given a SCEP server that asks Intune about every request
        And Intune answers with HTTP 429
        When a device enrolls with the challenge Intune handed out
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

    Scenario: The CA refuses after Intune allowed
        Given a SCEP server that asks Intune about every request
        When a device enrolls asking for keyCertSign and cRLSign
        Then the server answers FAILURE with failInfo badRequest
        And Intune received the failure notification

    Scenario: A request without a challenge password is not sent to Intune
        Given a SCEP server that asks Intune about every request
        When a device enrolls without a challenge password
        Then the server answers FAILURE with failInfo badRequest
        And Intune was not asked

    Scenario: The validation service is discovered through Graph and the token is reused
        Given a SCEP server that asks Intune about every request
        When a device enrolls with the challenge Intune handed out
        And another device enrolls with the challenge Intune handed out
        Then the validation service was discovered once
        And a token for the Intune resource was requested once
        And every Intune call carried the api-version "2018-02-20"

    Scenario: A renewal signed with the previous certificate passes without Intune
        Given a SCEP server that asks Intune about every request
        And a device holding a certificate issued through Intune
        When the device renews it with a new key
        Then the server answers SUCCESS
        And Intune was asked once in total

    Scenario: The app authenticates with a certificate instead of a secret
        Given a SCEP server that asks Intune about every request, authenticating with a certificate
        When a device enrolls with the challenge Intune handed out
        Then the server answers SUCCESS
        And every token was requested with an assertion signed by that certificate
