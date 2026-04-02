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
- Passed: `50`
- Failed: `9`
- Skipped: `5`

The skipped scenarios are the conditional/optional cases that are not implemented in the current server build, such as `/fullcmc`, certificate-less TLS mutual authentication, and root key rollover.

## Failing tests and current non-conformance

### 5. `/csrattrs` authentication, status codes, encoding, and RFC 9908 updates

**Failing scenarios**
- `RFC 7030 Section 4.5.2 defines the status codes for CSR attributes availability`
- `RFC 7030 Section 4.5.2 requires unrecognized CSR attributes to be ignored by clients`
- `RFC 7030 Section 4.5.2 defines empty CSR attributes semantics`
- `RFC 7030 Section 4.5.2 requires algorithm and POP requirements to be signaled explicitly`
- `RFC 9908 Section 3.2 constrains legacy extension requirements in the unstructured CSR attributes response`
- `RFC 9908 Section 3.4 constrains template-based extension requirements`

**Current non-conformance**
- `/csrattrs` always returns `200`; `204` / `404` unavailability semantics are not implemented.
- `EstClient.GetCsrAttributes()` expects only the template form and does not gracefully ignore unknown legacy `CsrAttrs` elements.
- The default CSR-attributes loader path does not emit the explicit legacy/template requirements needed for `id-ExtensionReq`, `challengePassword`, and related RFC 9908/RFC 7030 signaling scenarios.
- `src/opencertserver.ca.utils/X509/Templates/CertificateSigningRequestTemplate.cs` still has `// TODO: Support CRIAttributes`, so RFC 9908 extension/template attribute handling is incomplete.
- The codebase does not implement the `id-ExtensionReq` / `id-aa-extensionReqTemplate` coexistence rules described by RFC 9908.

**Suggested fix**
- Return `204` or `404` when no CSR attributes are available.
- Extend `CertificateSigningRequestTemplate` to support RFC 9908 CRI attributes and extension templates.
- Update `EstClient.GetCsrAttributes()` so newer clients prefer the template form and ignore unknown legacy elements.
- Emit the explicit legacy/template CSR-attribute requirements needed for `challengePassword`, `id-ExtensionReq`, and template extension constraints.

## Scenarios currently passing

Representative passing areas from the focused run:
- mandatory `/simpleenroll` and `/simplereenroll` route support;
- basic authenticated EST enrollment and re-enrollment happy paths already covered by the existing test harness;
- RFC 7030 simple enrollment and re-enrollment response semantics, including manual authorization, renewal, and rekey handling;
- RFC 8951 request/response base64 updates for `/csrattrs` and `/serverkeygen`, including base64 private-key delivery and Content-Transfer-Encoding tolerance;
- several request-shape checks for simple enrollment;
- multipart response presence for `/serverkeygen`;
- some RFC 9908 template subject/key presence checks where the current test loader can generate a simple template.

## Notes for future TDD work

Recommended implementation order:
1. Fix `/serverkeygen` encrypted-delivery metadata validation and CMS EnvelopedData packaging.
2. Fix `/csrattrs` status code behavior for unavailable and empty responses.
3. Update `EstClient.GetCsrAttributes()` to ignore unknown legacy CSR-attribute elements.
4. Add RFC 9908 CRI attribute and extension-template support.

