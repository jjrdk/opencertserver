@iq
@blackbox
@linux-client
@hardened
Feature: Issued certificates carry the CDP, AIA and OCSP extensions a hardened install embeds
When a Linux client enrolls through the ACME or EST service of a hardened installation, the
certificate it receives must carry the extension a relying party needs to find its status:
CRL Distribution Point (CDP), Authority Information Access (AIA: OCSP + caIssuers), and the
OCSP responder's own signature verification. These are not asserted in an isolated CA test;
they are what the certificate a Linux client actually receives shows, and the client observes
them with `openssl x509 -text`.

They complement the in-process certificate profile suite; the new assertion is that the
*client-observable* certificate carries the responder URLs the install embedded.

Rule: the OCSP URL is carried as an AIA OCSP responder

Scenario: A certificate issued through ACME carries the OCSP AIA responder
    Given a hardened OpenCertServer is reachable
    And an issued certificate is obtained through ACME for "acme.example.com"
    When the Linux client inspects the certificate with "openssl x509 -text"
    Then the extension Authority Information Access lists the OCSP responder URL "http://localhost:6001/ocsp"

Rule: the CA issuer(s) are carried as AIA caIssuers

Scenario: A certificate issued through ACME carries the caIssuers AIA
    And an issued certificate is obtained through ACME for "acme.example.com"
    When the Linux client inspects the certificate with "openssl x509 -text"
    Then the extension Authority Information Access caIssuers lists the URL "http://localhost:6001/ca/ca.pem"

Rule: the CRL URL is carried as a CDP

Scenario: A certificate issued through ACME carries the CRL distribution point
    And an issued certificate is obtained through ACME for "acme.example.com"
    When the Linux client inspects the certificate with "openssl x509 -text"
    Then the extension CRL Distribution Points lists the URL "http://localhost:6001/ca/crl.pem"

Scenario: A certificate issued through EST carries the same responder URLs
    Given a hardened OpenCertServer is reachable
    When the Linux client enrolls "est.example.com" through EST's "simpleenroll" endpoint
    Then the returned AIA and CRL distribution points match the ACME-issued certificate

Rule: a configured profile's fixed extensions are applied to the issued certificate.

Scenario: A configured profile fixes extensions on the issued certificate
    Given a hardened OpenCertServer with a fixed-extension profile configured
    When the Linux client issues a certificate through that profile
    Then the extended key usage extension equals the configured values
    And the certificate policies extension equals the configured values
