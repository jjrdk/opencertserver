# `opencertserver.certserver.tests`

## EST conformance suite

The project now contains an executable RFC-driven EST conformance suite in `Features/EstConformance.feature`.

It is intended to be used in a TDD style:
- the scenarios are fully bound and executable;
- passing scenarios describe behavior the current implementation already satisfies;
- failing scenarios identify concrete EST non-conformance in the current implementation rather than missing step definitions.

## Focused run

```zsh
dotnet test tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj --filter "FullyQualifiedName~EstConformance"
```

## Latest focused run result

Verified in this workspace:
- Total: `64`
- Passed: `56`
- Failed: `3`
- Skipped: `5`

The skipped scenarios are the conditional/optional cases that are not implemented in the current server build, such as `/fullcmc`, certificate-less TLS mutual authentication, and root key rollover.

## Failing tests and current non-conformance

### 4. Optional server-side key generation behavior

**Failing scenarios**
- `RFC 7030 Section 4.4.1 requires key-delivery metadata when additional encryption is requested`
- `RFC 7030 Sections 4.4.1.1 and 4.4.1.2 require errors when the requested key-encryption material is unavailable`

**Current non-conformance**
- The server still accepts encrypted `serverkeygen` requests without requiring DecryptKeyIdentifier / AsymmetricDecryptKeyIdentifier and `SMIMECapabilities`.
- The application-layer encrypted private-key delivery modes from RFC 7030 are still not implemented; only the response part shape is negotiated today.

**Suggested fix**
- Reject encrypted key-delivery requests that omit the required key-identification metadata.
- Implement CMS EnvelopedData packaging for server-generated-key responses when additional application-layer encryption is requested.

## Scenarios currently passing

Representative passing areas from the focused run:
- mandatory `/simpleenroll` and `/simplereenroll` route support;
- basic authenticated EST enrollment and re-enrollment happy paths already covered by the existing test harness;
- RFC 7030 simple enrollment and re-enrollment response semantics, including manual authorization, renewal, and rekey handling;
- `/csrattrs` authentication, status codes, RFC 8951 base64 encoding, client parsing, and RFC 9908 template/legacy requirement scenarios;
- RFC 8951 request/response base64 updates for `/csrattrs` and `/serverkeygen`, including base64 private-key delivery and Content-Transfer-Encoding tolerance;
- several request-shape checks for simple enrollment;
- multipart response presence for `/serverkeygen`;
- some RFC 9908 template subject/key presence checks where the current test loader can generate a simple template.

## Notes for future TDD work

Recommended implementation order:
1. Fix `/serverkeygen` encrypted-delivery metadata validation.
2. Implement CMS EnvelopedData packaging for application-layer encrypted private-key delivery.

