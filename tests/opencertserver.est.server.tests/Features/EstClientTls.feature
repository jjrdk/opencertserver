@est-client-tls
Feature: EST client authenticates using TLS rather than certificate headers

    Scenario Outline: Default transport isolates anonymous and certificate identities
        Given an EST client with a real TLS server and "<algorithm>" identity
        When the TLS client first makes an "<initial>" request
        And the TLS client renews using "<key>" key material
        Then renewal uses the existing certificate over a new TLS connection
        And certificate enrollment and anonymous CA retrieval use isolated TLS connections

        Examples:
          | algorithm | initial          | key          |
          | RSA       | cacerts          | public       |
          | ECDsa     | cacerts          | public       |
          | RSA       | anonymous enroll | renewal      |
          | ECDsa     | anonymous enroll | renewal      |
          | RSA       | cacerts          | existing     |
          | ECDsa     | cacerts          | existing     |
          | RSA       | bootstrap        | renewal      |
          | ECDsa     | bootstrap        | renewal      |

    Scenario Outline: Public certificate and unrelated renewal key cannot authenticate
        Given an EST client with a real TLS server and "<algorithm>" identity
        When the TLS client renews a public certificate with an unrelated private key
        Then the client rejects the mismatched key without sending a request

        Examples:
          | algorithm |
          | RSA       |
          | ECDsa     |

    Scenario Outline: Failed TLS enrollment retires the client identity
        Given an EST client with a real TLS server and "<algorithm>" identity
        When a TLS certificate request is "<failure>" after reaching the server
        Then subsequent CA retrieval does not present the failed request's certificate

        Examples:
          | algorithm | failure   |
          | RSA       | cancelled |
          | ECDsa     | cancelled |
          | RSA       | aborted   |
          | ECDsa     | aborted   |
