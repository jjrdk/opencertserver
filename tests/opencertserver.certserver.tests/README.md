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
- Passed: `38`
- Failed: `21`
- Skipped: `5`

The skipped scenarios are the conditional/optional cases that are not implemented in the current server build, such as `/fullcmc`, certificate-less TLS mutual authentication, and root key rollover.

## Failing tests and current non-conformance

### 4. RFC 8951 wire-format updates

**Failing scenarios**
- `RFC 8951 requires EST endpoints to ignore Content-Transfer-Encoding header values` for endpoints that still depend on legacy formatting behavior
- `RFC 7030 Section 4.5.2 and RFC 8951 define the CSR attributes response encoding`
- `RFC 7030 Section 4.4.2 and RFC 8951 define the unencrypted private key response part`
- `RFC 7030 Section 4.4.2 and RFC 8951 define the encrypted private key response part`

**Current non-conformance**
- Several handlers still emit raw DER or PEM while setting headers that imply MIME-era transfer semantics.
- `src/opencertserver.est.server/Handlers/CertificateSigningRequestTemplateResult.cs` writes raw DER bytes to the response body and sets `Content-Transfer-Encoding: base64` rather than actually returning RFC 4648 base64 text.
- `src/opencertserver.est.server/Handlers/ServerKeyGenHandler.cs` returns a multipart response whose private-key part is raw PKCS#8 bytes, not RFC 4648 base64 text.

**Suggested fix**
- Normalize all EST request/response payloads that RFC 8951 updates to RFC 4648 base64 text over DER.
- Remove dependence on `Content-Transfer-Encoding` semantics and treat the header as informational/ignored.
- Update `CertificateSigningRequestTemplateResult` and `ServerKeyGenHandler` to emit actual base64 text bodies.

---

### 5. Optional server-side key generation behavior

**Failing scenarios**
- `RFC 7030 Section 4.4.1 requires key-delivery metadata when additional encryption is requested`
- `RFC 7030 Sections 4.4.1.1 and 4.4.1.2 require errors when the requested key-encryption material is unavailable`
- `RFC 7030 Section 4.4.2 requires the certificate part to match simple enrollment semantics`

**Current non-conformance**
- The server accepts a bare `serverkeygen` request without requiring DecryptKeyIdentifier / AsymmetricDecryptKeyIdentifier and `SMIMECapabilities`.
- The encrypted-key delivery modes from RFC 7030 are not implemented.
- The certificate part is returned as PEM chain text instead of matching the EST simple enrollment certificate response.

**Suggested fix**
- Reject encrypted key-delivery requests that omit the required key-identification metadata.
- Implement CMS EnvelopedData packaging for server-generated-key responses.
- Align the certificate part with the same certs-only CMC response used by `/simpleenroll`.

---

### 6. `/csrattrs` authentication, status codes, encoding, and RFC 9908 updates

**Failing scenarios**
- `RFC 7030 Sections 4.5 and 4.5.1 define the /csrattrs request and its authentication expectations`
- `RFC 7030 Section 4.5.2 defines the status codes for CSR attributes availability`
- `RFC 7030 Section 4.5.2 and RFC 8951 define the CSR attributes response encoding`
- `RFC 7030 Section 4.5.2 requires unrecognized CSR attributes to be ignored by clients`
- `RFC 7030 Section 4.5.2 defines empty CSR attributes semantics`
- `RFC 7030 Section 4.5.2 requires algorithm and POP requirements to be signaled explicitly`
- `RFC 9908 Section 3.2 constrains legacy extension requirements in the unstructured CSR attributes response`
- `RFC 9908 Section 3.4 constrains template-based extension requirements`

**Current non-conformance**
- `src/opencertserver.est.server/EstServerExtensions.cs` protects `/csrattrs` with authorization by default, while RFC 7030 says the server SHOULD NOT require it.
- `/csrattrs` always returns `200`; `204` / `404` unavailability semantics are not implemented.
- `CertificateSigningRequestTemplateResult` returns raw DER instead of RFC 8951 base64 text.
- `EstClient.GetCsrAttributes()` expects only the template form and does not gracefully ignore unknown legacy `CsrAttrs` elements.
- `src/opencertserver.ca.utils/X509/Templates/CertificateSigningRequestTemplate.cs` still has `// TODO: Support CRIAttributes`, so RFC 9908 extension/template attribute handling is incomplete.
- The codebase does not implement the `id-ExtensionReq` / `id-aa-extensionReqTemplate` coexistence rules described by RFC 9908.

**Suggested fix**
- Make `/csrattrs` anonymously readable by default, or at minimum configurable to be anonymous.
- Return `204` or `404` when no CSR attributes are available.
- Encode the response body as RFC 4648 base64 DER.
- Extend `CertificateSigningRequestTemplate` to support RFC 9908 CRI attributes and extension templates.
- Update `EstClient.GetCsrAttributes()` so newer clients prefer the template form and ignore unknown legacy elements.

## Scenarios currently passing

Representative passing areas from the focused run:
- mandatory `/simpleenroll` and `/simplereenroll` route support;
- basic authenticated EST enrollment and re-enrollment happy paths already covered by the existing test harness;
- RFC 7030 simple enrollment and re-enrollment response semantics, including manual authorization, renewal, and rekey handling;
- several request-shape checks for simple enrollment;
- multipart response presence for `/serverkeygen`;
- some RFC 9908 template subject/key presence checks where the current test loader can generate a simple template.

## Notes for future TDD work

Recommended implementation order:
1. Fix `/cacerts` routing and CMC/base64 formatting.
2. Fix simple enrollment response shape and re-enrollment CSR handling.
3. Fix `/csrattrs` encoding and status code behavior.
4. Add RFC 9908 CRI attribute support.
5. Tighten TLS / trust-anchor / POP linkage handling.
6. Complete `/serverkeygen` encrypted delivery support.

