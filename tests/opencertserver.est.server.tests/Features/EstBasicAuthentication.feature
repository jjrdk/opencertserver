Feature: EST enrollment with a user name and password (RFC 7030 §3.2.3)
    RFC 7030 lets an EST server authenticate a client with HTTP Basic over TLS, next to a
    certificate. The server offers it only where users are configured; the identity it produces is
    the user name, and the password is held as a PBKDF2 hash.

    Scenario: A configured user enrolls with the right password
        Given a certificate server where the user "vpn.example.org" has the password "a long passphrase"
        When the client "vpn.example.org" with the password "a long passphrase" submits a rsa CSR for "CN=vpn.example.org"
        Then the server returns a signed certificate

    Scenario: A wrong password is refused and the challenge names the scheme
        Given a certificate server where the user "vpn.example.org" has the password "a long passphrase"
        When the client "vpn.example.org" with the password "wrong" submits a rsa CSR for "CN=vpn.example.org"
        Then the server answers 401 and challenges with Basic

    Scenario: A user the server does not know is refused
        Given a certificate server where the user "vpn.example.org" has the password "a long passphrase"
        When the client "someone.else" with the password "a long passphrase" submits a rsa CSR for "CN=someone.else"
        Then the server answers 401 and challenges with Basic

    Scenario: Without configured users the password way is off
        Given a certificate server that complies with EST (RFC 7030)
        When the client "vpn.example.org" with the password "a long passphrase" submits a rsa CSR for "CN=vpn.example.org"
        Then the server answers 401 without a Basic challenge

    Scenario: A users file that cannot be read turns the password way off instead of failing every request
        Given a certificate server whose Basic users file cannot be read
        When the client "vpn.example.org" with the password "a long passphrase" submits a rsa CSR for "CN=vpn.example.org"
        Then the server answers 401 without a Basic challenge

    Scenario: A password hash verifies its password and no other
        When the password "a long passphrase" is hashed
        Then the hash verifies "a long passphrase" and refuses "a long passphrasE"
        And the hash starts with "pbkdf2-sha256$"
