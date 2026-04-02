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
- Passed: `60`
- Failed: `0`
- Skipped: `4`

The skipped scenarios are the conditional/optional cases that are not implemented in the current server build, such as `/fullcmc` and certificate-less TLS mutual authentication.

## Failing tests and current non-conformance

The focused EST conformance scenarios currently pass in this workspace. The remaining skipped scenarios are optional or conditional features that are not implemented in this test server configuration, such as `/fullcmc` and certificate-less TLS mutual authentication.

## Scenarios currently passing

Representative passing areas from the focused run:
- mandatory `/simpleenroll` and `/simplereenroll` route support;
- basic authenticated EST enrollment and re-enrollment happy paths already covered by the existing test harness;
- RFC 7030 simple enrollment and re-enrollment response semantics, including manual authorization, renewal, and rekey handling;
- `/csrattrs` authentication, status codes, RFC 8951 base64 encoding, client parsing, and RFC 9908 template/legacy requirement scenarios;
- RFC 8951 request/response base64 updates for `/csrattrs` and `/serverkeygen`, including base64 private-key delivery, Content-Transfer-Encoding tolerance, and encrypted key-delivery request validation;
- several request-shape checks for simple enrollment;
- multipart response presence for `/serverkeygen`;
- some RFC 9908 template subject/key presence checks where the current test loader can generate a simple template.

## Notes for future TDD work

Recommended implementation order:
1. Add optional `/fullcmc` support if desired.
2. Add optional certificate-less TLS mutual authentication support if desired.
3. Extend any future optional scenarios beyond the currently passing rollover coverage if desired.

