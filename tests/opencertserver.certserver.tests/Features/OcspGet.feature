@ocsp
@rfc6960
Feature: OCSP GET request encodings
    RFC 6960 Appendix A.1 and RFC 5019 section 5 require URL-encoded standard base64.
    Existing base64url clients remain supported, and unescaped slashes reach the responder.

    Scenario Outline: OCSP GET accepts standard and legacy encodings with special characters
        Given a certificate server
        When an OCSP client sends a GET request using "<Encoding>" with base64 special characters
        Then the OCSP responder MAY accept the GET request
        And the OCSP responder MUST return the "application/ocsp-response" media type
        And the OCSP response status MUST be "successful"
        And the corresponding SingleResponse MUST report the certificate status as good

        Examples:
          | Encoding           |
          | url-encoded base64 |
          | base64             |
          | base64url          |
          | padded base64url    |

    Scenario Outline: Invalid OCSP GET data returns an OCSP malformedRequest response
        Given a certificate server
        When an OCSP client sends a GET request with invalid encoded data "<Data>"
        Then the OCSP responder MUST return the "application/ocsp-response" media type
        And the OCSP responder MUST return the OCSP response status "malformedRequest"
        And the malformed request response MUST NOT include responseBytes

        Examples:
          | Data       |
          | not!base64 |
          | A===       |
          | AQID       |
          | %ZZ        |
