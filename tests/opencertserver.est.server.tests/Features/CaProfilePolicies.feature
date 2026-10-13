Feature: Certificate content fixed by the CA profile (RFC 5280 §4.2.1.3, §4.2.1.4, §4.2.1.12)
    A CA profile can fix what every certificate it issues says: the certificate policies it asserts,
    the key usage and the extended key usages. What the profile fixes replaces what the CSR asked for;
    a policy is never taken from a CSR, because it is the CA's assertion and not the requester's.

    Scenario: A profile without policies writes no certificatePolicies extension
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a valid rsa certificate signing request (CSR) using the "rsa" certificate profile
        Then the issued certificate carries no certificatePolicies extension

    Scenario: The policies a profile asserts are written into every certificate it issues
        Given a certificate server whose "rsa" profile is configured with:
            | setting             | value                                      |
            | CertificatePolicies | 1.3.6.1.4.1.67091.10.1, 1.3.6.1.4.1.67091.10.4 |
        When a client submits a valid rsa certificate signing request (CSR) using the "rsa" certificate profile
        Then the issued certificate carries exactly the certificate policies "1.3.6.1.4.1.67091.10.1, 1.3.6.1.4.1.67091.10.4"

    Scenario: A policy requested in the CSR is never taken over, even when the profile lists its OID as allowed
        Given a certificate server whose "rsa" profile is configured with:
            | setting              | value                                     |
            | AllowedCsrExtensions | 2.5.29.17, 2.5.29.37, 2.5.29.15, 2.5.29.32 |
            | CertificatePolicies  | 1.3.6.1.4.1.67091.10.1                    |
        When a client submits a rsa CSR to the "rsa" profile that asks for the policy "1.3.6.1.4.1.67091.10.2"
        Then the issued certificate carries exactly the certificate policies "1.3.6.1.4.1.67091.10.1"

    Scenario: The key usage a profile fixes replaces the one the CSR asked for
        Given a certificate server whose "rsa" profile is configured with:
            | setting  | value            |
            | KeyUsage | DigitalSignature |
        When a client submits a rsa CSR to the "rsa" profile that asks for the key usage "DigitalSignature, KeyEncipherment, DataEncipherment"
        Then the issued certificate's key usage is exactly "DigitalSignature" and critical

    Scenario: The extended key usages a profile fixes replace the ones the CSR asked for
        Given a certificate server whose "rsa" profile is configured with:
            | setting           | value             |
            | ExtendedKeyUsages | 1.3.6.1.5.5.7.3.2 |
        When a client submits a rsa CSR to the "rsa" profile that asks for the extended key usage "1.3.6.1.5.5.7.3.1"
        Then the issued certificate's extended key usages are exactly "1.3.6.1.5.5.7.3.2"

    Scenario: A profile that issues intermediate CA certificates asserts anyPolicy on them
        Given a certificate server whose "rsa" profile is configured with:
            | setting              | value                         |
            | AllowedCsrExtensions | 2.5.29.17, 2.5.29.19, 2.5.29.15 |
            | CertificatePolicies  | 2.5.29.32.0                   |
        When a client submits a rsa CSR to the "rsa" profile that asks for a CA certificate
        Then the issued certificate is a CA certificate
        And the issued certificate carries exactly the certificate policies "2.5.29.32.0"
