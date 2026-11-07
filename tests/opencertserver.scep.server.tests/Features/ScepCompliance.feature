Feature: The SCEP server behaves to RFC 8894 at the edges
  The happy path is covered in ScepServer.feature. This file locks the edge cases a strict
  reader of RFC 8894 would probe: the message types and message shapes the server must refuse
  without crashing, the failure CertRep's echoing of the request, the Windows /pkiclient.exe
  mapping, and the replay window in both directions.

Scenario Outline: An unsafe transaction ID is refused before logging or replying in SCEP
  Even a signed request's transactionID is untrusted. It must fit the reply's PrintableString
  encoding and length limit, including before the unsupported-cipher badAlg path.
  Given a certificate server that complies with SCEP (RFC 8894)
  When a client enrolls with a "<Value>" transaction ID encoded as "<Encoding>" using "<Cipher>"
  Then the server answers HTTP 400
  And exactly one safe SCEP rejection is logged

  Examples:
    | Value                     | Encoding        | Cipher |
    | newline                   | UTF8String      | 3DES   |
    | newline                   | IA5String       | 3DES   |
    | newline                   | UTF8String      | AES    |
    | newline                   | IA5String       | AES    |
    | carriage return           | UTF8String      | AES    |
    | tab                       | IA5String       | AES    |
    | null                      | UTF8String      | AES    |
    | non-PrintableString ASCII | IA5String       | AES    |
    | Unicode                   | UTF8String      | AES    |
    | empty                     | PrintableString | AES    |
    | too long                  | PrintableString | AES    |
    | too long                  | UTF8String      | AES    |
    | too long                  | IA5String       | AES    |

Scenario Outline: PrintableString-safe transaction IDs remain interoperable
  Hex and base64 IDs, all PrintableString characters, and the exact length limit are accepted.
  UTF8String and IA5String clients remain supported when their values are PrintableString-safe.
  Given a certificate server that complies with SCEP (RFC 8894)
  When a client enrolls with a "<Value>" transaction ID encoded as "<Encoding>" using "AES"
  Then the server answers SUCCESS
  And the response echoes the supplied transaction ID

  Examples:
    | Value                    | Encoding        |
    | hex                      | PrintableString |
    | base64                   | PrintableString |
    | PrintableString alphabet | PrintableString |
    | PrintableString alphabet | UTF8String      |
    | PrintableString alphabet | IA5String       |
    | minimum length           | PrintableString |
    | maximum length           | PrintableString |
    | maximum length           | UTF8String      |
    | maximum length           | IA5String       |

Scenario: A senderNonce longer than 16 bytes is refused
  RFC 8894, 3.2.1.1.1 fixes the senderNonce to 16 bytes.
  Given a certificate server that complies with SCEP (RFC 8894)
  When a client enrolls with a senderNonce of 17 bytes
  Then the server answers HTTP 400

Scenario: A refused request still echoes the transaction id and the client's nonce
  RFC 8894, 3.2.1.2 and 3.2.1.4: the CertRep carries the transactionID, the recipientNonce, the
  pkiStatus and, on failure, the failInfo - even when nothing is issued.
  Given a certificate server that complies with SCEP (RFC 8894)
  When a client enrolls without a challenge password
  Then the server answers FAILURE with failInfo badRequest
  And the response echoes the transaction ID and the client's nonce
  And no certificate is returned

Scenario: A CertPoll request is refused with failInfo badRequest
  RFC 8894, 3.5.3: this server has no pending-request store, so a CertPoll answers a failure.
  Given a certificate server that complies with SCEP (RFC 8894)
  When a client enrolls with an unsupported messageType "20"
  Then the server answers FAILURE with failInfo badRequest
  And no certificate is returned

Scenario: A messageType that is not defined is refused with HTTP 400
  A messageType outside the RFC 8894 set is malformed, not a CertPoll, so it is a 400.
  Given a certificate server that complies with SCEP (RFC 8894)
  When a client enrolls with an unsupported messageType "99"
  Then the server answers HTTP 400

Scenario: A Windows client reads the capabilities through /pkiclient.exe
  RFC 8894, 3.5.2 and the Windows /pkiclient.exe mapping.
  Given a certificate server that complies with SCEP (RFC 8894)
  When a Windows client asks for the capabilities at "/scep/pkiclient.exe"
  Then the capabilities include "POSTPKIOperation", "SHA-256" and "Renewal"

Scenario: A request that two signers have signed is refused
  RFC 8894, 3.2.1: a pkiMessage has exactly one signer. A second signature is a malformed message.
  Given a certificate server that complies with SCEP (RFC 8894)
  When a client enrolls with a request that two signers have signed
  Then the server answers HTTP 400

Scenario: A PKCSReq whose content is not a certificate request is refused
  A PKCSReq carrying bytes that are not a CSR cannot be processed; the server must refuse it, not crash.
  The message itself is verified and decrypted, so the refusal is a signed CertRep with badRequest
  (RFC 8894, 3.2.1.4) the client can match to its transaction, not an HTTP error.
  Given a certificate server that complies with SCEP (RFC 8894)
  When a client enrolls with a request whose content is not a certificate request
  Then the server answers FAILURE with failInfo badRequest
  And no certificate is returned
  When a client enrolls with the challenge password "geheim" using the "rsa" profile
  Then the server answers SUCCESS

Scenario: A request under an older transaction id is accepted once the window has elapsed
  RFC 8894, 3.2.1.5: the replay guard is time-bounded. The same request that was refused while the
  window held is accepted once the window has elapsed - the guard proves itself in both directions.
  Given a certificate server that complies with SCEP (RFC 8894)
  When a client enrolls with the challenge password "geheim" using the "rsa" profile
  And the replay window has elapsed
  And the same request is sent again
  Then the server answers SUCCESS
