Feature: Certificate server compliance with SCEP (RFC 8894)

    Scenario: SCEP capabilities emit metrics and a tag-free trace
        Given the certificate server storage is "in-memory"
        And a certificate server that complies with SCEP (RFC 8894)
        And a SCEP OpenTelemetry listener
        When a client asks for the CA capabilities
        Then the SCEP capabilities metric and trace are recorded without attributes

    Scenario: PKIOperation refusals count as protocol failures
        Given the certificate server storage is "in-memory"
        And a certificate server that complies with SCEP (RFC 8894)
        And a SCEP OpenTelemetry listener
        When a client enrolls asking for basicConstraints CA:TRUE and keyCertSign
        Then the server answers FAILURE with failInfo badRequest
        And the SCEP PKIOperation failure metric and trace are recorded

    Scenario Outline: The server announces its capabilities
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client asks for the CA capabilities
        Then the capabilities include "POSTPKIOperation", "SHA-256" and "AES"

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: The server publishes the RA certificate before the CA certificate
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client asks for the CA certificates
        Then the response is a CA/RA certificate bundle
        And the first certificate is the RA certificate
        And the bundle contains the CA certificate

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # Below a root, GetCACert carries the published chain, root included. Windows looks
    # for the root thumbprint of its Intune profile in this response and gives up before
    # sending a request when it is missing ("The hash value is not correct", 0x80091007).
    Scenario Outline: The server publishes the root above an issuing CA
        Given the certificate server storage is "<Storage>"
        And a certificate server with SCEP whose CA is issued by a root
        When a client asks for the CA certificates
        Then the first certificate is the RA certificate
        And the bundle contains the CA certificate
        And the bundle contains the root certificate

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: Enrollment with the right challenge password
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "<challenge>" using the "<profile>" profile
        Then the server answers SUCCESS
        And the response echoes the transaction ID and the client's nonce
        And the issued certificate has the requested subject
        And the issued certificate is issued by the "<profile>" CA

        Examples:
          | profile | challenge | Storage    |
          | rsa     | geheim    | in-memory  |
          | rsa     | geheim    | postgresql |
          | rsa     | geheim    | mssql      |

    # Windows creates RSA keys for SCEP. Since #111 the CA signs a request whose key
    # algorithm differs from its own, so an ECDSA profile can serve SCEP clients.
    Scenario Outline: An RSA request against an ECDSA profile is issued by the CA
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "geheim" using the "ecdsa" profile
        Then the server answers SUCCESS
        And the issued certificate is issued by the "ecdsa" CA

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # Windows appends /pkiclient.exe to the SCEP server URL configured in Intune, with or
    # without a profile in it.
    Scenario Outline: A Windows client reaches the profile of the configured URL
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "geheim" at "<path>"
        Then the server answers SUCCESS
        And the issued certificate is issued by the "<profile>" CA

        Examples:
          | path                      | profile | Storage    |
          | /scep/pkiclient.exe       | rsa     | in-memory  |
          | /scep/pkiclient.exe       | rsa     | postgresql |
          | /scep/pkiclient.exe       | rsa     | mssql      |
          | /scep/ecdsa/pkiclient.exe | ecdsa   | in-memory  |
          | /scep/ecdsa/pkiclient.exe | ecdsa   | postgresql |
          | /scep/ecdsa/pkiclient.exe | ecdsa   | mssql      |

    Scenario Outline: Enrollment through GET
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls through GET with the challenge password "geheim"
        Then the server answers SUCCESS

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: A wrong challenge password is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "falsch" using the "rsa" profile
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: A request without a challenge password is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls without a challenge password
        Then the server answers FAILURE with failInfo badRequest

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: A request encrypted to a key other than the RA is rejected
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with a request encrypted to a foreign certificate
        Then the server rejects the message with HTTP 400

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: The user principal name from the request is carried into the certificate
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with a subject alternative name UPN "anna@example.at"
        Then the server answers SUCCESS
        And the issued certificate contains the UPN "anna@example.at"

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # Whoever knew the challenge used to get a subordinate CA: the CA core took
    # basicConstraints CA:TRUE and keyCertSign over from the CSR.
    Scenario Outline: A request for a CA certificate is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls asking for basicConstraints CA:TRUE and keyCertSign
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: The server offers renewal
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client asks for the CA capabilities
        Then the capabilities include "Renewal", "SHA-256" and "AES"

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # RFC 8894, 3.3.1.2: a RenewalReq is signed with the certificate it renews. That
    # certificate is the proof - no challenge password is needed.
    Scenario Outline: A certificate is renewed with the certificate it replaces
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile
        When the client renews it with a new key
        Then the server answers SUCCESS
        And the renewed certificate has the same subject and a new key
        And the previous certificate is revoked

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # Before #96 the CA core accepted reenrollingFrom by issuer name alone. A certificate
    # signed by another key under the same CA name must not pass as proof.
    Scenario Outline: A renewal signed with a look-alike certificate is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client renews with a certificate from a look-alike CA of the same name
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # The certificate that signs a RenewalReq is the proof, and an expired certificate proves
    # nothing: the chain check treats a certificate outside its validity period as an error.
    Scenario Outline: A renewal signed with an expired certificate of this CA is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client renews with an expired certificate from this CA
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # Profiles may share one CA key (#140): a certificate renews through the profile that
    # issued it, as with EST.
    Scenario Outline: A renewal through another profile of the same CA is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile
        When the client renews it through the "rsa-shared" profile
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # The issuing CA sits in the profile's CertificateChain, its root only in the published
    # chain: the renewal check has to reach the root through the published chain.
    Scenario Outline: A certificate from an issuing CA below a root is renewed
        Given the certificate server storage is "<Storage>"
        And a certificate server with SCEP whose CA is issued by a root
        And a client holding a certificate from the "rsa" profile
        When the client renews it with a new key
        Then the server answers SUCCESS
        And the renewed certificate has the same subject and a new key

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: A renewal for another subject is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile
        When the client renews it for the subject "CN=Anderes Geraet, O=entra-vpn"
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # As for EST simplereenroll (RFC 7030, 4.2.2): the renewal names what the certificate
    # it renews names. The profile copies the subjectAltName from the request.
    Scenario Outline: A certificate with a subject alternative name is renewed with the same name
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile with the UPN "anna@contoso.test"
        When the client renews it with the UPN "anna@contoso.test"
        Then the server answers SUCCESS
        And the renewed certificate has the same subject and a new key

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: A renewal for another subject alternative name is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile with the UPN "anna@contoso.test"
        When the client renews it with the UPN "bert@contoso.test"
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: A renewal that drops the subject alternative name is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile with the UPN "anna@contoso.test"
        When the client renews it without a subject alternative name
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: A renewal with a revoked certificate is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        And a client holding a certificate from the "rsa" profile
        And that certificate is revoked
        When the client renews it with a new key
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # A captured request must not have the CA issue a second time.
    Scenario Outline: A replayed transaction is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "geheim" using the "rsa" profile
        And the same request is sent again
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # Only a request that passed its checks is remembered: a refused one takes no room, so
    # the same transaction ID and nonce still go through with the right challenge.
    Scenario Outline: A refused request is not remembered
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "falsch" using the "rsa" profile
        And a client enrolls with the challenge password "geheim" using the "rsa" profile
        Then the server answers SUCCESS

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # The anonymous endpoint cannot grow the store without bound: when it is full and
    # nothing has expired, a new request is refused rather than risk a replay.
    Scenario Outline: A full replay store refuses new requests
        Given the certificate server storage is "<Storage>"
        And a certificate server with SCEP that remembers at most 1 request
        When a client enrolls with the challenge password "geheim" using the "rsa" profile
        And another client enrolls with the challenge password "geheim" under a new transaction
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # The signature holds, but a signed attribute has the wrong ASN.1 type.
    Scenario Outline: A malformed signed attribute is rejected as a bad request
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client sends a request whose senderNonce is encoded as an INTEGER
        Then the server rejects the message with HTTP 400

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # Clients derive the transaction ID from the public key (RFC 8894, 3.2.1.1.1): a new
    # request with the same key - a renewal, a retry - carries the earlier ID with a new nonce.
    Scenario Outline: A new request under an earlier transaction ID is accepted
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "falsch" using the "rsa" profile
        And the client tries again with the challenge password "geheim", the same transaction ID and a new nonce
        Then the server answers SUCCESS

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # certserver wires SCEP in by default. Until a challenge is configured, the endpoint
    # publishes its certificates but issues nothing.
    Scenario Outline: A server without a challenge validator issues nothing
        Given the certificate server storage is "<Storage>"
        And a certificate server with SCEP but no challenge validator
        When a client enrolls with the challenge password "geheim" using the "rsa" profile
        Then the server answers FAILURE with failInfo badRequest
        And no certificate is returned

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    # RFC 8894, 3.5.2: the capability "AES" promises AES128-CBC, and 2.9 makes it
    # mandatory. The reply is encrypted with the algorithm the request used, so a
    # client always gets back what it can read.
    Scenario Outline: The reply is encrypted with the algorithm of the request
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "geheim" and the request encrypted with "<algorithm>"
        Then the server answers SUCCESS
        And the reply is encrypted with "<algorithm>"

        Examples:
          | algorithm   | Storage    |
          | AES-128-CBC | in-memory  |
          | AES-128-CBC | postgresql |
          | AES-128-CBC | mssql      |
          | AES-192-CBC | in-memory  |
          | AES-192-CBC | postgresql |
          | AES-192-CBC | mssql      |
          | AES-256-CBC | in-memory  |
          | AES-256-CBC | postgresql |
          | AES-256-CBC | mssql      |

    # The capabilities offer AES only. A request in anything else is refused, not decrypted:
    # RFC 8894, 3.2.1.4, failInfo badAlg, in a signed CertRep the client can match.
    Scenario Outline: A request encrypted with an algorithm the capabilities do not offer is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with the challenge password "geheim" and the request encrypted with "<algorithm>"
        Then the server answers FAILURE with failInfo badAlg
        And no certificate is returned

        Examples:
          | algorithm | Storage    |
          | 3DES-CBC  | in-memory  |
          | 3DES-CBC  | postgresql |
          | 3DES-CBC  | mssql      |
          | DES-CBC   | in-memory  |
          | DES-CBC   | postgresql |
          | DES-CBC   | mssql      |

    # RFC 8894, 3.2.1: senderNonce is a 16-byte random number.
    Scenario Outline: A senderNonce that is not 16 bytes is refused
        Given the certificate server storage is "<Storage>"
        And a certificate server that complies with SCEP (RFC 8894)
        When a client enrolls with a senderNonce of 8 bytes
        Then the server answers HTTP 400

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |
