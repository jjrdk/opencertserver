# opencertserver.iq.tests — Installation Qualification

These are **Installation Qualification (IQ)** scenarios, not unit or conformance tests.

Their purpose is to prove that a *deployed, hardened, full-featured* OpenCertServer
installation behaves correctly **when driven by a real client**, the way an operator
or a relying party would use it in the field. They are deliberately *black-box*:
the under-test is a **running server reached over the network**, reached from a
**Linux client**, using **standard Linux tools** rather than the in-process `.NET`
harness the conformance and correctness suites use.

## Why this is different from the other suites

| Suite | Under-test | How it is driven |
|---|---|---|
| `opencertserver.certserver.tests`, `opencertserver.<proto>.tests` | in-process `WebApplicationFactory`/`TestServer` | .NET `EstClient`, `AcmeContext`, direct handler calls |
| `opencertserver.mcp.tests` | in-process MCP host | .NET tool invocations |
| **`opencertserver.iq.tests` (this project)** | **a running OpenCertServer container over HTTP/TLS** | **a Linux container running `estclient`, `openssl`, `curl`, `acme.sh`, `certbot`, `jq`, and the `opencert` CLI** |
| **MCP IQ feature** | **the published standalone MCP executable, launched in Linux** | **JSON-RPC over subprocess stdin/stdout, with independent OpenSSL checks** |

The goal is **complementarity, not duplication**: the RFC-conformance and
correctness scenarios already lock the protocol behaviour down to the byte.
These IQ scenarios re-state the *feature* from the outside — "can I actually use
this from a machine, over the wire, against my deployment?" — and add the
deployment posture a real install needs (TLS pinning, `no Server` header, health
probe, CAA fail-closed, device-attestation fail-closed, metrics actually emitted).
Every referenced RFC/feature here is *the same capability* the conformance suite
covers; the new information is that it is **reachable and correct from a Linux
client over the network**.

## Execution model (the design the scenarios describe)

Two TestContainers images are orchestrated by the step definitions:

1. **Server image** — a running, hardened OpenCertServer built from the repository
   root [`Dockerfile`](../../Dockerfile), hardened with TLS 1.2/1.3 only, no
   `Server` header, CAA enforcement on, device attestation fail-closed, EST Basic
   auth configured, and a profile that fixes some `certificatePolicies` /
   `keyUsage` / `extendedKeyUsage`. It is reached on an ephemeral HTTPS port.
2. **Client image** — [`client/Dockerfile`](./client/Dockerfile): an Ubuntu
   26.04 image that installs the standard tools via `apt` plus Cisco libest's EST client,
   built from the Ubuntu package sources, the ACME client
   `acme.sh` (fetched over curl, the canonical ACME client), EFF `certbot` (from `apt`)
   and the project's own `opencert` CLI. Every scenario's Given/When/Then is something
   this image can execute: `estclient`, `curl`, `openssl`, `acme.sh`, `certbot`, `jq`, `opencert`.

A [`docker-compose.yml`](./docker-compose.yml) provides a manual equivalent of the
same two-container topology for hands-on runs; TestContainers performs the same
bring-up programmatically.

MCP is the stdio exception to the network topology: it reuses the client image and
publish infrastructure, but needs no HTTP server, DNS container or private network.

> **Status.** The ACME feature ([`AcmeIssuance.feature`](./Features/AcmeIssuance.feature))
> is implemented: [`Support/IqAcmeEnvironment.cs`](./Support/IqAcmeEnvironment.cs) builds the
> images, starts a private network, an authoritative test DNS server
> ([`acme/dns_server.py`](./acme/dns_server.py)), the hardened server and the client with
> TestContainers (random host ports, no compose), and
> [`StepDefinitions/AcmeIssuanceSteps.cs`](./StepDefinitions/AcmeIssuanceSteps.cs) runs
> `acme.sh`, `certbot`, curl, openssl and jq inside the client. The certbot rule repeats the
> account, http-01/dns-01 issuance, EAB, renewal and revocation lifecycle with a second ACME
> client; each scenario uses its own `--config-dir`/`--work-dir`/`--logs-dir` under the
> scenario work directory, and the EAB scenario uses its own single-use key (`iq-eab-certbot`).
> [`AuthorityInformation.feature`](./Features/AuthorityInformation.feature) is also implemented
> by [`StepDefinitions/AuthorityInformationSteps.cs`](./StepDefinitions/AuthorityInformationSteps.cs):
> all five scenarios reuse the same topology and lifecycle hooks, with the file-backed issuing
> profiles described below. All three [`CaaEnforcement.feature`](./Features/CaaEnforcement.feature)
> scenarios are implemented by
> [`StepDefinitions/CaaEnforcementSteps.cs`](./StepDefinitions/CaaEnforcementSteps.cs), reusing the
> ACME steps and topology with per-scenario CAA configuration isolation.
> All six [`CrlRevocation.feature`](./Features/CrlRevocation.feature) scenarios are implemented by
> [`StepDefinitions/CrlRevocationSteps.cs`](./StepDefinitions/CrlRevocationSteps.cs), reusing the
> feature lifecycle, file-backed issuing profiles and Linux client, with a disposable OIDC issuer
> and CRL distribution relay as described below.
> All four [`OcspResponder.feature`](./Features/OcspResponder.feature) cases are implemented by
> [`StepDefinitions/OcspResponderSteps.cs`](./StepDefinitions/OcspResponderSteps.cs), reusing
> that topology and enrollment/revocation flow with OpenSSL OCSP signature and status checks.
> All six [`EstEnrollment.feature`](./Features/EstEnrollment.feature) scenarios are implemented by
> [`StepDefinitions/EstEnrollmentSteps.cs`](./StepDefinitions/EstEnrollmentSteps.cs), using the same
> topology, issuing profiles, signed JWTs and online-revocation relay with estclient and openssl.
> All eight [`LinuxServerDeployment.feature`](./Features/LinuxServerDeployment.feature) cases are
> implemented by [`StepDefinitions/LinuxServerDeploymentSteps.cs`](./StepDefinitions/LinuxServerDeploymentSteps.cs),
> reusing the topology and lifecycle with an opt-in HTTP listener for redirect qualification.
> All five [`McpServer.feature`](./Features/McpServer.feature) scenarios are implemented by
> [`StepDefinitions/McpServerSteps.cs`](./StepDefinitions/McpServerSteps.cs), launching the
> published MCP executable as a real stdio subprocess inside the Linux client.
> All six [`OpenCertCli.feature`](./Features/OpenCertCli.feature) scenarios are implemented by
> [`StepDefinitions/OpenCertCliSteps.cs`](./StepDefinitions/OpenCertCliSteps.cs), running the
> published Linux CLI with independent OpenSSL/Python output checks.
> All three [`OpenTelemetry.feature`](./Features/OpenTelemetry.feature) scenarios are implemented
> by [`StepDefinitions/OpenTelemetrySteps.cs`](./StepDefinitions/OpenTelemetrySteps.cs), scraping
> a real OTLP collector after Linux traffic and inspecting its exported enrollment spans.
> All six [`ProfileIssuance.feature`](./Features/ProfileIssuance.feature) cases are implemented by
> [`StepDefinitions/ProfileIssuanceSteps.cs`](./StepDefinitions/ProfileIssuanceSteps.cs), using
> named-profile EST enrollment, conflicting CSRs and independent OpenSSL checks, including
> rejection of unauthorised CA issuance.
> All four [`DeviceAttestation.feature`](./Features/DeviceAttestation.feature) scenarios are
> implemented by [`StepDefinitions/DeviceAttestationSteps.cs`](./StepDefinitions/DeviceAttestationSteps.cs),
> reusing the ACME topology and Linux raw client with disposable manufacturer roots and independently
> signed software TPM-quote fixtures.
> The test-only deviations (non-private
> 198.18.0.0/15 subnet for http-01, private DNS, separate TLS PKI, TOS timing) are described in
> [`acme-harness-plan.md`](../../acme-harness-plan.md). The remaining features have no step
> definitions yet and are reported as undefined.
>
> Run the ACME feature (requires Docker; the first run publishes and builds both images):
>
> ```sh
> dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
>   --filter-class "OpenCertServer.Iq.Tests.Features.RFC8555ACMEIssuanceWorksForALinuxWeb_ApplicationClientFeature"
> ```
>
> `IQ_SERVER_IMAGE` / `IQ_CLIENT_IMAGE` select prebuilt images; `IQ_DOCKER_ARCH` (`x64`/`arm64`)
> overrides the detected Docker architecture.

### Certificate-server penetration scenarios

[`CertificateServerSecurity.feature`](./Features/CertificateServerSecurity.feature) implements
16 strict perimeter probes, adapted from the sibling `opencertserver-server` solution's
`tests/opencertserver.yarp.pentest.tests/Features/ProxySecurity.feature`.
[`PenetrationSteps`](./StepDefinitions/PenetrationSteps.cs) reuses the YARP suite's
OpenSSL peer-alert checks, Nmap XML cipher inventory, bounded tool execution and raw
TLS/HTTP probe design. The raw Python helper is adapted from its `Scanner/raw_request.py`.

The feature reuses `IqAcmeEnvironment`, `IqImages`, the generated TLS PKI, DNS, scenario
state and `AcmeIssuanceHooks` rather than building another deployment harness. The
**real `opencertserver.certserver` runs in the server container** with its production
perimeter policies; this feature also enables the existing opt-in HTTP listener. **Every
penetration tool runs in the Linux IQ client container**, including OpenSSL, curl,
Nmap's `ssl-enum-ciphers` NSE script and Python's raw TLS socket probe. Nmap is installed
by the shared client Dockerfile; no scanner tools are needed on the host. The existing
Testcontainers server-readiness check still runs on the host, not as a penetration probe.
Targets are fixed to the isolated server's Docker alias, not a public or configurable
remote deployment.

| Probe | Certificate-server requirement |
|---|---|
| TLS-01 / TLS-02 | Peer rejection of TLS 1.0 / 1.1; local crypto errors are inconclusive, not a pass |
| TLS-03 / TLS-04 | TLS 1.2 / 1.3 negotiation with trusted chain and hostname |
| TLS-05 | Rejection of the static RSA `AES128-SHA` CBC suite |
| TLS-06 | Non-empty Nmap inventory without legacy protocols, static RSA, CBC, anonymous, NULL, export, RC4, DES or MD5 suites |
| HTTP-01 | HTTP redirects preserve method, encoded path and query without trusting forged forwarding headers |
| HTTP-02 | HSTS `max-age` of at least 15552000 on health, ACME, EST and missing resources |
| HTTP-03 | No `Server` or `X-Powered-By` banners |
| HTTP-04 | TRACE receives 405 without reflecting a witness header on CA, EST and ACME routes |
| HTTP-05 | Missing/invalid credentials receive 401/403 on CA issuance/revocation and EST enrollment/re-enrollment/key generation |
| HTTP-06 | Unrecognized Host values are rejected before either serving HTTPS or redirecting HTTP |
| HTTP-07 | A valid but untrusted certificate supplied through identity headers cannot authorize those protected operations |
| HTTP-08 | Conflicting Content-Length/Transfer-Encoding and duplicate Content-Length are rejected with connection close and no appended response; valid framing still reaches authentication |
| HTTP-09 | Scanner paths, `.git/config` and `appsettings.json` receive 403/404 |
| HTTP-10 | A 64 KiB header receives 400/431 |

YARP-specific tenant-cache authorization becomes CA/EST authorization; proxy certificate
stripping becomes denial of forged certificate identity; scanner-path checks assert no
application/configuration disclosure rather than proxy upstream isolation. There is no
echo upstream in this topology: framing evidence covers responses on one TLS connection,
not proof of upstream request execution. Like the reference suite, HTTP-08 deliberately
requires rejection of CL+TE even though RFC 9112 also permits normalization.

Run from the repository root with Docker available. This invokes the native xUnit
runner because the installed MTP runner can select zero tests with class/trait filters:

```sh
dotnet build tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj
mkdir -p artifacts/iq
dotnet run --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj --no-build -- \
  -class "OpenCertServer.Iq.Tests.Features.CertificateServerPerimeterSecurityFromALinuxScannerFeature" \
  -xml artifacts/iq/pentest-results.xml
```

Do not use an older `IQ_CLIENT_IMAGE` override unless it includes Nmap and the NSE scripts.
By default the harness rebuilds the server and client images, including the new tool.
Tools have an in-container deadline as well as host cancellation (90 seconds for Nmap,
20 seconds for other tools); raw TLS sockets also have time and response-size bounds.
Empty inventories, timeouts, missing tools and invalid TLS identity fail explicitly.
There is no report-only mode, skipped finding, or test-only server-policy override.
Scenario output and the XML report retain observations and failed-server diagnostics.

**Verified local result (2026-10-19): all 16 pentests and all 69 other IQ scenarios pass
together, with no skips.** The production host now restricts Linux/OpenSSL ciphers to
AEAD suites, publishes 180-day HSTS, filters Host values before redirects, rejects
ambiguous framing before authentication, and selects JWT/mTLS authentication with a
defined challenge scheme. The shared environment supplies its exact Docker host aliases
through `AllowedHosts`, including the secondary TOS/attestation server and localhost
readiness checks; it does not override the production security policies.

To repeat the complete regression run and preserve its per-scenario output:

```sh
dotnet build tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj
mkdir -p artifacts/iq
dotnet run --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj --no-build -- \
  -xml artifacts/iq/all-iq-hardened-results.xml
```

See [the host perimeter reference](../../docs/documentation.md#host-perimeter-and-deployment-configuration)
for deployment settings and the Linux-specific cipher policy.

### Device-attestation scenarios

Run all four device-attestation scenarios (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.TheDevice_Attest_01ChallengeIsAdvertisedAndFailsClosedFeature"
```

The feature reuses `IqAcmeEnvironment`, its private network, TLS trust, Linux client and lifecycle
hooks. The default server retains the empty trust provider: curl/jq require directory advertisement,
then signed newOrder and POST-as-GET requests verify that every returned authorization offers
exactly `dns-01` and `http-01`. Orders use the supported DNS identifier `device.example.com`;
the server does not define a separate hardware identifier type or a newOrder challenge selector.

The evidence scenarios generate a disposable manufacturer root and an RSA AIK certificate/key
inside the Linux client with OpenSSL. A scenario-owned second server receives **only the public
root** through the normal `Attestation__TrustAnchors__0` PEM-file setting. Its existing second-server
TLS alias is reused; TLS verification stays enabled. Neither system trust nor the issuing CA is
used as manufacturer trust, and no validator, authorization factory or store is replaced.

[`client/scripts/device-attest.py`](./client/scripts/device-attest.py) uses Python's standard-library
`struct` to encode a size-prefixed TPM2B_ATTEST quote containing the real challenge nonce. OpenSSL
signs it with RSA-PKCS1v15/SHA-256 and independently verifies the AIK chain and signature. These are
**software-generated fixtures**, not hardware attestations: this feature qualifies the deployed
ACME evidence transport, configured-root integration, signed-quote acceptance and replay rejection,
not TPM key custody, genuine manufacturer provenance, platform measurements or native attestation.
The synthetic PCR digest is not evidence of a measured boot.

The negative scenario sends both an empty proof and malformed TPM bytes on separate fresh
challenges, each with a matching nonce and trusted AIK. Both must become `invalid` with the full
`invalid_attestation` ACME error URN and the **proof-verification** diagnostic, rather than failing
earlier at authentication, nonce or chain verification. The positive/replay scenario requires a
`valid` challenge and validation timestamp before resubmitting the exact evidence with a **fresh
outer JWS nonce**. That second submission must return HTTP 400 `application/problem+json` with
`replay_nonce`; POST-as-GET must still return the original valid challenge unchanged. This is
distinct from replaying an ACME transport nonce (`badNonce`).

Challenge outcomes are polled with a 30-second deadline; client commands are bounded to 90 seconds.
Failures include the response body, last client output and server/DNS logs. Both servers and all
client-only private keys disappear with container teardown. `IQ_SERVER_IMAGE`, `IQ_CLIENT_IMAGE`
and `IQ_DOCKER_ARCH` work as for ACME; helpers are mounted from the working tree, so helper changes
do not require rebuilding the client image.

### MCP-stdio scenarios

Run all five MCP scenarios (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.TheMCPServerExposesTheCAOverStdioAndFailsClosedFeature"
```

[`Support/IqMcpEnvironment.cs`](./Support/IqMcpEnvironment.cs) reuses `IqImages` to publish a
self-contained MCP host for the Linux architecture and obtain the existing Ubuntu client image.
It copies the host into a fresh client container for each scenario; no MCP project reference,
in-process tool call, `dotnet run`, HTTP proxy or replacement CA is used.
`IQ_CLIENT_IMAGE` selects a prebuilt client; `IQ_DOCKER_ARCH` applies to the MCP publish too.
The MCP host is always freshly published from the working tree, with trimming disabled for
SDK reflection-based tool discovery. No client-image rebuild is needed for MCP helper changes.

[`client/scripts/mcp-stdio.py`](./client/scripts/mcp-stdio.py) uses Python's standard library
to launch the actual executable, perform `initialize` / `notifications/initialized`, then send
newline-delimited JSON-RPC `tools/list` and `tools/call` requests on that subprocess's stdin.
It correlates response IDs, bounds requests/startup to 30 seconds, and keeps stdout protocol
traffic separate from stderr logs. A container-local Unix socket lets the bindings drive the
same live subprocess across Given/When/Then; it is not the MCP transport. Teardown closes stdin,
waits for exit and disposes the client container. Failures include stderr and response transcripts.

The default read-only scenario leaves all MCP security options unset. The explicit-disabled
scenario sets `McpServer:EnableCaOperations=false`. Both require all eight read-only tools to
be advertised and both destructive tools to be absent; calling the absent signing tool must
return JSON-RPC `-32602` with `Unknown tool: 'sign_certificate'`. This is an invalid `name`
parameter to the existing `tools/call` method, not `-32601` (unknown JSON-RPC method).
The missing-token scenario explicitly enables CA operations and opts into the test CA, but
omits the token; it requires a nonzero process exit, no stdout and the specific token-required
startup diagnostic.

The CRL and signing scenarios explicitly enable CA operations, supply a fresh random token
and opt into `McpServer:AllowSelfSignedTestCa=true`. The standalone MCP host currently has
no external CA-key loader and only registers its CA on this enabled path. Thus the CRL scenario
qualifies a read-only operation on a configured CA, not an unconfigured read-only host returning
live CA data. The disposable self-signed CA and in-memory store are test-only; this feature does
not qualify production key custody or durable storage. No authentication or authorization check
is disabled. The token authenticates the stdio process's caller; it is not a per-tool bearer token.

OpenSSL decodes the returned base64 DER CRL and verifies its signature against CA certificates
retrieved from the same MCP session. Signing uses an OpenSSL-generated RSA CSR whose CN matches
the configured caller (`mcp-caller`); OpenSSL verifies the returned leaf's chain and DNS name,
compares its public key with the generated private key and checks its serial against the tool
metadata. Successful data scenarios reject both JSON-RPC errors and MCP `isError` tool results.

### OpenCert CLI scenarios

Run all six CLI scenarios (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.TheOpencertCLIRunsAsALinuxBinaryThatDrivesTheServerFeature"
```

The feature reuses the ACME topology/lifecycle, file-backed issuing profiles, disposable OIDC
issuer and CRL relay. Every scenario checks that `opencert` is an ELF executable running on Linux,
then invokes the self-contained binary installed in the client image, never `dotnet run` or
in-process `Program.Main`. Each scenario has an isolated working directory; renewal performs
its own initial enrollment. Commands have a 60-second timeout and retain their real exit status.
No new image, server substitute or production project reference is needed.

- `hash-password` reads a synthetic password from stdin. Python's standard-library PBKDF2
  independently recomputes the digest, checking the algorithm, default 600,000 iterations,
  decoded salt/digest sizes and supplied password, not merely a prefix.
- `generate-keys` and `create-csr` produce an RSA private/public pair and PKCS#10 request.
  OpenSSL validates the private key, compares all public keys in DER form (ignoring PEM whitespace),
  checks the requested subject/SAN and verifies the CSR signature.
- `print-cert` reads an independently OpenSSL-generated certificate. Its subject block must name
  that certificate's CN and organization; both printed validity timestamps must match OpenSSL.
- `est-enroll` uses CLI-generated keys and a signed JWT with a matching authenticated CN.
  All EST commands pin the disposable **TLS** root with `--ta-mode explicit --est-ca`; this root
  is distinct from the issuing CA. TLS chain and hostname validation remain enabled.
  OpenSSL verifies the resulting non-CA client-authentication leaf against the independently
  curl-retrieved `/cacerts` bundle and compares it with the generated private key.
  This qualifies CN identity; the CLI's current enrollment API does not forward SAN options.
- `est-server-certificates` must print a nonempty PEM CA bundle. OpenSSL verifies every CA and
  compares the complete set of DER fingerprints with the separately retrieved `/cacerts` bundle.
- `est-reenroll` receives the original certificate and matching private key, with no JWT.
  The renewed leaf must verify, match the same key and subject, and have a different serial.
  The current EST client sends `X-Client-Cert`, which the standalone server's certificate-forwarding
  middleware accepts. This qualifies that existing renewal path, **not TLS client-key possession**;
  the separate estclient feature exercises real mTLS. Online server-side certificate revocation
  checking remains enabled through the existing CRL relay.

Success assertions require usable, independently verified output and explicit success messages for
enrollment/renewal, not only exit zero: several CLI commands currently print errors without setting
a failing process exit code. These network tests also cover EST enrollment's MIME
`Content-Transfer-Encoding: base64`, which must not be sent as HTTP `Transfer-Encoding`.
`IQ_SERVER_IMAGE`, `IQ_CLIENT_IMAGE` and `IQ_DOCKER_ARCH` work as for ACME; prebuilt client images
must contain the current CLI binary. Failure diagnostics include client output and server/DNS/issuer logs.

### OpenTelemetry scenarios

Run all three telemetry scenarios (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.OpenTelemetrySignalsAreActuallyEmittedAfterRealTrafficFeature"
```

The feature reuses the ACME topology, feature lifecycle, file-backed issuing profiles, Linux
client and existing OCSP/enrollment helpers. It opts into an additional
`otel/opentelemetry-collector-contrib:0.123.0` container on the private network. Its health
extension must be ready before the server starts. Other features keep telemetry disabled and
do not start a collector. The normal server image is used without production project references,
in-process listeners, replacement instruments or mock exporters.

The server uses its existing `Telemetry:Enabled`, `Telemetry:OtlpEndpoint` and
`Telemetry:ServiceName` settings to export real OTLP/gRPC signals to `http://telemetry:4317`,
with service name `opencertserver-iq`. Test-only SDK environment settings shorten metric export
to one second and span batching to 200 ms, with always-on sampling. OTLP and Prometheus ports
remain internal to the Docker network; only the collector health port receives a random host
binding. Collector logs join the existing server/DNS/issuer diagnostics on failures.

curl in the Linux client scrapes the collector's Prometheus exporter at
`http://telemetry:8889/metrics` before traffic and polls for increments afterward, with a
30-second deadline rather than a fixed sleep. Assertions require Prometheus counter types
and positive changes from the scenario's baseline, not just instrument presence or old totals.
Prometheus normalizes dotted names to underscores and appends `_total`:
`opencertserver.est.cacerts.requests` becomes `opencertserver_est_cacerts_requests_total`,
and `opencertserver.ocsp.request.requests` becomes `opencertserver_ocsp_request_requests_total`.

- The endpoint scenario fetches and decodes `/cacerts`, enrolls its own certificate and uses
  the existing OpenSSL OCSP helper to require a signed, verified `good` response for that leaf.
  The OCSP-responder section's documented POST TLS-peer limitation also applies here.
- The outcome scenario posts a valid CSR and an intentionally malformed base64 CSR with the
  same valid Basic-auth credentials. The first must produce an independently verified
  client-authentication certificate matching its private key; the second must return HTTP 400
  from the EST handler, not fail authentication before instrumentation. Exported request,
  success and failure counters must all increase, with at least two new requests.
- The trace scenario sends a fresh, sampled W3C `traceparent` with the enrollment request.
  The collector's file exporter writes OTLP JSON to a disposable container-local file; the
  test runner reads that exported artifact through Docker, not the server's in-process API.
  It polls for the exact trace ID, EST instrumentation scope, `opencertserver-iq` service and
  `opencertserver.est.simpleenroll` span, requiring an OK status, nonzero span ID and positive
  duration. An unrelated request or another scenario's enrollment cannot satisfy the assertion.

Enrollment and CA-bundle retrieval use verified HTTPS and the existing ephemeral Basic-auth
identity with a matching CSR CN. OpenSSL verifies the returned PKCS#7 certificate against the
published issuer and compares its public key with the generated private key. No client-image
changes are needed; `IQ_SERVER_IMAGE`, `IQ_CLIENT_IMAGE` and `IQ_DOCKER_ARCH` retain their
existing meanings. The collector and its export file are disposed with the feature topology.

### Linux-deployment scenarios

Run all eight deployment cases (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.ADeployedHardenedOpenCertServerIsReachableAndHealthyOverTLSFromALinuxClientFeature"
```

The feature reuses the ACME network, DNS, hardened server, trusted TLS PKI, Linux client and
failure diagnostics. It opts into Kestrel's documented endpoint configuration to add an
internal-only `http://opencertserver:6000` listener alongside HTTPS on port 6001; other features
retain their HTTPS-only setup. No proxy simulates the redirect: curl checks the server's 3xx
status and exact HTTPS `Location`, then verifies that destination returns `Healthy`.

The TLS outline explicitly exercises both TLS 1.2 and TLS 1.3 with `openssl s_client`.
Each requires the requested negotiated version, a successful exit, and certificate verification
against the disposable TLS root with hostname and server-authentication checks. TLS 1.0/1.1
attempts lower **only the client's** cipher security level to allow a real legacy ClientHello;
they must fail with the server's protocol-version alert, not a local cipher error or timeout.
TLS checks are never bypassed for successful connections.

curl checks `/health` returns HTTP 200 and `Healthy`, and makes a real GET to `/cacerts` while
capturing headers (`-sS -D -`, rather than `-I`, which sends HEAD). The header scenario requires
HTTP 200 as well as absence of a case-insensitive `Server` field. The publication scenario
requires RFC 7030's `application/pkcs7-mime; smime-type=certs-only`, base64-decodes the body,
parses the DER PKCS#7 with OpenSSL and checks for a nonempty CA certificate bundle.
The published issuing CA is distinct from the TLS trust root, as in the ACME feature.

### EST-enrollment scenarios

Run all six EST scenarios (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.RFC7030ESTEnrollmentWorksForALinuxDeviceClientFeature"
```

Every EST operation runs Cisco libest's real
[`estclient`](https://manpages.ubuntu.com/manpages/resolute/man1/estclient.1.html),
not curl or an in-process EST library. OpenSSL independently inspects and verifies the output.
`EST_OPENSSL_CACERT` points the client at the disposable TLS root; TLS verification stays enabled.
Each scenario has its own working directory, keys and certificates; re-enrollment performs its
initial enrollment in the same scenario. The sample executable returns zero even on some protocol
failures, so the bindings also check success/error messages and the resulting files.

- `estclient -g` fetches `cacerts` anonymously, decoded from base64 DER PKCS#7 and split into individual
  CA certificates. Each CA must have `CA:TRUE` and verify against the published bundle.
- `estclient -e -y <csr> --auth-token <jwt>` uses an ephemeral, signed JWT with the device's authenticated name
  `est.example.com`. The existing disposable HTTPS OIDC issuer provides discovery and signing
  keys; signature, issuer, audience and expiration validation remain enabled. The issued
  leaf must be non-CA, have the requested DNS SAN and client-auth EKU, chain to the published CA,
  and match the client's private key.
- `estclient -r -c <cert> -k <key>` presents only the initially issued certificate/key over mTLS.
  This client renews the existing key, rather than re-keying. The new certificate must have a
  different serial and match that key.
  The existing HTTP CRL relay lets the server perform normal online revocation checking;
  neither certificate authentication nor revocation checking is bypassed.
- The EST fixture configures `Est:CsrAttributesFile` with a DER RFC 9908 version-0 template
  requiring an unfilled commonName. `estclient -a` saves the response; the scenario checks its ASN.1
  structure, supplies that commonName in a CSR and successfully enrolls with `estclient -e`.
  This does not claim that libest interprets RFC 9908 templates automatically.
  Without this opt-in setting, the standalone
  host retains its default HTTP 204 response.
- `estclient -q -x <key> --common-name <name> --auth-token <jwt>` requests server-keygen.
  Libest parses the multipart response and writes a PKCS#8 RSA key and PKCS#7 certificate.
  The scenario checks that the generated key matches the verifiable certificate and differs
  from the client's original key. Libest 3.2.0 does not support encrypted CMS key delivery:
  that path remains covered by the existing EST conformance suite, not this IQ scenario.
- `estclient -e -u <user> -h <password> --pem-output` uses Basic authentication and converts the
  PKCS#7 response to a PEM leaf on the client. The scenario checks that it verifies and matches
  the client's key; it does not exercise the host's separate PEM content-negotiation extension.

The image builds the exact sources behind Ubuntu's `libest-utils 3.2.0+ds-1.1`, verifies both
source archives with SHA-256, and retains the upstream license. It is **not the unmodified Ubuntu
binary**: the build omits the distribution's HTTP/1.0-only patch, which rejects Kestrel's valid
HTTP/1.1 responses. [`client/libest-compat.patch`](./client/libest-compat.patch) fixes double-encoded
Bearer tokens, accommodates signed JWT lengths, selects Basic when only Basic credentials are
configured, and accepts unwrapped base64 in the CA/PEM decoders. Patches must apply without fuzz.
No compatibility patch disables authentication, TLS verification or certificate verification.
The server supplies explicit response lengths for CSR attributes and multipart key delivery, and
emits the MIME `smime-type` token without unnecessary quotes, for libest interoperability.

[`client/scripts/est-crypto.py`](./client/scripts/est-crypto.py) uses only Python's standard library
to inspect the advertised DER template. All cryptographic operations and certificate/key checks
run through OpenSSL in the Linux container. The helper is mounted by the harness, so prebuilt
client images need no rebuild to pick up helper changes. Prebuilt images must include the patched
`estclient`. Failure output includes the last client command and server, DNS and issuer/relay logs.

### Profile-controlled issuance scenarios

Run all six profile cases (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.Profile_ControlledCertificateContentIsWhatTheClientReceivesFeature"
```

The feature reuses the ACME topology, lifecycle, TLS PKI and file-backed RSA/ECDSA issuers.
Only this feature opts into fixed policy `1.3.6.1.4.1.999`, critical KU
`KeyEncipherment,DataEncipherment` and server-authentication-only EKU on both profiles.
Other features retain their existing profile settings. Each scenario has its own working
directory, private key, CSR and output; no scenario relies on another scenario's enrollment.

OpenSSL generates and verifies CSRs containing deliberately conflicting policy, KU and EKU.
Cisco libest's `estclient -e -y` enrolls over verified TLS using the disposable Basic user.
`--path-seg rsa` / `--path-seg ecdsa` selects the actual named profile; the EC row also uses
an EC P-256 request key. The client image enables libest's upstream URI-parser support
(`--with-uriparser-dir=/usr`, `liburiparser-dev` / `liburiparser1`); prebuilt client images
must be rebuilt to support named-profile requests. Authentication and TLS checks remain enabled.

OpenSSL decodes the PKCS#7 output, verifies the leaf's chain and DNS name against the same
profile's separately retrieved `estclient -g` CA bundle, and compares the issued public key
with the request key as DER. Bounded `openssl x509 -text` extension blocks require exact
policy/KU/EKU contents and critical KU; the algorithm rows inspect the leaf public-key
algorithm. Success requires both the estclient success marker and usable output, not just
its process exit code. Failures retain client output and the existing server/DNS diagnostics.

The CA:TRUE scenario submits a verified CSR containing critical `basicConstraints=CA:TRUE`.
It requires estclient's HTTP 400 / `EST_ERR_HTTP_BAD_REQ` result and no issued certificate.
Since libest omits the error body, curl repeats the same signed CSR over verified TLS with
the same credentials and requires HTTP 400 with the exact reason
`CSR must not request CA:TRUE in basicConstraints`. An authentication or parsing failure
cannot satisfy this assertion.

The original draft expected a silently downgraded `CA:FALSE` leaf. The scenario now asserts
rejection, matching [the CA issuance opt-in policy](../../docs/standards.md#csr-extension-allow-list-allowedcsrextensions)
and the existing `CsrWithCaTrueIsRejected` CA test. Successful enrollment scenarios separately
require critical `CA:FALSE`. No validator is disabled and production behavior is unchanged.

### Authority-information scenarios

Run all five CDP/AIA/profile scenarios (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.IssuedCertificatesCarryTheCDPAIAAndOCSPExtensionsAHardenedInstallEmbedsFeature"
```

[`Support/IqAuthorityConfiguration.cs`](./Support/IqAuthorityConfiguration.cs) opts this feature
into disposable RSA/ECDSA issuing CAs loaded through `--rsa` / `--ec`, rather than `--dn`
(the self-signed shortcut does not load fixed profile extensions). The default `rsa` profile
sets server/client authentication EKUs and policy `1.3.6.1.4.1.9999.1` using the host's
documented root-level `rsa:ExtendedKeyUsages` and `rsa:CertificatePolicies` settings.
The ACME feature retains its original self-signed setup.

The client obtains each ACME certificate with `acme.sh --standalone`; EST uses an ephemeral
Basic-auth identity over verified TLS, with the CSR CN matching the authenticated name.
`curl` posts a base64 PKCS#10 CSR to `simpleenroll` (or `rsa/simpleenroll` for the explicit
profile scenario), and `openssl` decodes the returned PKCS#7 and verifies the certificate
against the CA published by `cacerts`. Certificate assertions parse individual extension
blocks from `openssl x509 -text`, requiring nonempty blocks and exact values. The fixed-profile
scenario requests conflicting EKUs/policies to prove replacement by the configured values.
The EST/ACME comparison obtains both certificates in the same scenario, so it never relies on
another scenario's artifacts or execution order.

The asserted `http://localhost:6001/...` URLs are the hardened configuration's literal
certificate metadata. These tests do not dereference those URLs from the Linux container:
enrollment and CA-chain retrieval use the verified `https://opencertserver:6001` service.

### CAA-enforcement scenarios

Run all three CAA scenarios (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.CAAEnforcementRFC8659RFC8657IsObservableThroughTheACMEPathFeature"
```

[`StepDefinitions/CaaEnforcementHooks.cs`](./StepDefinitions/CaaEnforcementHooks.cs) starts and
disposes a separate instance of the existing DNS/server/client topology for each scenario,
preventing CAA records, resolver caches and server settings from leaking between scenarios.
Enforcement scenarios explicitly set `AcmeServer:DisableCaaChecks=false` and advertise
`AcmeServer:CAAIdentities=["iq.test"]`, verified from the ACME directory with curl/jq.
The rejecting domain publishes `0 issue "other-ca.invalid"`; the accepting domain publishes
`0 issue "iq.test"`. An absent CAA RRset does **not** forbid issuance under RFC 8659.

The `@caa-disabled` scenario explicitly sets `AcmeServer:DisableCaaChecks=true` and leaves
`CAAIdentities` unset. This makes the opt-out observable: without it, the server's fail-closed
configuration check would reject issuance even for the CAA-less domain. The Given steps
check the directory has no identities and the private DNS zone has no applicable CAA records.

All issuance attempts run `acme.sh --standalone` with isolated account/config directories.
The rejection assertion requires a nonzero exit, no certificate, and an invalid `http-01`
challenge carrying `urn:ietf:params:acme:error:caa` in acme.sh's final logged JSON response.
This is an embedded ACME problem: challenge polling returns HTTP 200 `application/json`,
not a standalone HTTP error with `application/problem+json`. Successful scenarios verify
both the certificate chain against the CA published by `cacerts` and the requested DNS SAN
using openssl. Failure diagnostics include client output and server/DNS logs.

### CRL-publication and revocation scenarios

Run all six CRL scenarios (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.CRLPublicationAndRevocationRFC5280AreUsableFromLinuxFeature"
```

The feature shares the ACME topology/lifecycle and the authority-information feature's disposable
RSA/ECDSA profiles and EST Basic-auth identity. Each scenario has its own client working directory,
keys and enrolled certificates; no scenario depends on another scenario's artifacts or run order.
The client uses curl/openssl to enroll client-authentication certificates through EST, retrieve
the published issuer, and verify their chains before using them over real mTLS.

[`Support/IqRevocationConfiguration.cs`](./Support/IqRevocationConfiguration.cs) adds a test-only
Python container with HTTPS OIDC discovery and a JWKS endpoint. It generates an ephemeral signing
key and two short-lived, signed JWTs for the same operator, differing only in their role
(`ca_admin` versus `ca_reader`). The server trusts the issuer's TLS root and validates discovery,
signature, issuer, audience and expiration through its normal JWT handler. Administrative and
unauthorized requests present a different EST-issued certificate from the target, plus the
corresponding bearer token; self-service presents only the target certificate.

Every revocation request signs the exact hexadecimal serial plus `keyCompromise` using
`openssl dgst -sha256` and the presented certificate's key. curl URL-encodes the signature and query
parameters. OpenSSL's serial display omits the positive ASN.1 INTEGER sign-padding byte; the steps
restore it when required by the API's .NET serial representation before signing.

Both `/ca/rsa/crl` and `/ca/ecdsa/crl` must return HTTP 200 `application/pkix-crl` and a DER CRL whose
signature verifies against that profile's published issuer. Revocation scenarios fetch the CRL
before and after the attempt: successful revocation must add the exact serial and `Key Compromise`
reason, and `openssl verify -crl_check` must reject the certificate as revoked. A denied request
must return 403, leave the serial absent and leave the target certificate verifiable.

The configured CDP is `http://issuer:8080/ca/crl`. Linux/.NET online chain validation needs an HTTP
distribution point; the Python container relays **only** this public CRL path to the server over
verified HTTPS, without caching or generating CRLs itself. Enrollment and revocation still go
directly to the server over verified HTTPS. The CDP scenario checks the exact extension URI,
fetches that URI and verifies the returned CRL signature. Issuer/relay logs join server/DNS logs
on failure. No TLS checks, CA authorization checks or online revocation checks are disabled.

### OCSP-responder scenarios

Run all four OCSP cases (requires Docker):

```sh
dotnet test --project tests/opencertserver.iq.tests/opencertserver.iq.tests.csproj \
  --filter-class "OpenCertServer.Iq.Tests.Features.TheOCSPResponderRFC6960AnswersALinuxRelyingPartyFeature"
```

The feature reuses the ACME topology and lifecycle, file-backed RSA/ECDSA profiles and
CRL feature's enrollment and authenticated self-service revocation steps. Each case enrolls
its own RSA certificate through EST, retrieves its published issuer and verifies the chain.
The revoked case signs a `keyCompromise` request with that certificate's key and requires
successful revocation over real mTLS. The existing HTTP CRL relay keeps online certificate
validation enabled; enrollment and revocation retain verified TLS and normal authentication.

`openssl ocsp` sends POST requests directly to the running server's
`https://opencertserver:6001/ca/ocsp` endpoint, with its normal nonce verification.
OpenSSL has no GET option: for the GET row, it generates the DER request with `-reqout`,
curl transports it to `/ca/ocsp/{request}`, and OpenSSL parses and verifies the DER response
with `-respin`. This row uses the endpoint's current **unpadded base64url** path encoding,
not RFC 6960's percent-encoded standard base64; it qualifies this install's GET endpoint,
not conformance of that encoding. The GET request omits a nonce, as for cacheable requests.
curl verifies the GET transport's TLS certificate against the installed test root; this row
also requires HTTP 200 and `application/ocsp-response`. The native `openssl ocsp` HTTPS client
does not authenticate the TLS peer. Its POST result is authenticated by the independently
verified OCSP signature, not by TLS peer validation. This feature therefore does not qualify
TLS authentication by that OpenSSL subcommand; the deployment feature covers TLS independently.

Every response must have a successful OCSP status and OpenSSL's `Response verify OK`.
The signer is resolved only from the separately retrieved issuing CA (`-no_intern
-verify_other`), with that CA as the trust anchor and no fallback to system CA stores.
No signature or signer-authorization checks are disabled. OpenSSL checks freshness with
a five-second clock tolerance and a maximum status age of five minutes. Assertions match
the status line for the exact enrolled certificate, requiring `good` or `revoked`; revoked
responses must also carry `keyCompromise` and a revocation time. These scenarios qualify
issuer-signed OCSP responses, not a separately configured delegated responder.

## Client tool inventory (`client/Dockerfile`)

| Tool | Origin | Used by |
|---|---|---|
| `curl`, `wget` | `apt` (Ubuntu) | HTTP/HTTPS endpoint checks: ACME directory/order, CRL, OCSP, health; EST in other IQ features |
| `estclient` 3.2.0 | Ubuntu `libest-utils 3.2.0+ds-1.1` sources with [compatibility patches](./client/libest-compat.patch) and URI-parser support | EST operations in `EstEnrollment.feature` and named-profile enrollment in `ProfileIssuance.feature` |
| `openssl` | `apt` | certificate/CSR generation, `ocsp` and `crl` status checks, `x509 -text` content assertions |
| `ca-certificates` | `apt` | TLS verification of the server chain |
| `socat` | `apt` | `acme.sh --standalone` answers http-01 on port 80 |
| `acme.sh` 3.1.1 | pinned GitHub release tarball | RFC 8555 ACME issuance, revocation, EAB |
| `certbot` | `apt` (Ubuntu) | second RFC 8555 client: registration, EAB, `certonly --standalone` (http-01), `--manual` (dns-01), `renew`, `revoke` |
| `acme-raw.sh`, `dns_iq.sh`, `certbot-dns-iq.sh` | [`client/scripts`](./client/scripts) (mounted by the harness) | raw RFC 8555 requests (TOS re-agreement, missing nonce); acme.sh and certbot dns-01 hooks for the test DNS server |
| `jq` | `apt` | JSON response shaping (`/directory`, problem+json) |
| `python3`, `mcp-stdio.py` | `apt` / mounted [`client/scripts`](./client/scripts) helper | real MCP subprocess lifecycle, stdio JSON-RPC handshake and requests |
| `opencert` | repository CLI build | CLI sub-commands run *inside* the client as a native binary |

## Feature inventory

Each `.feature` file below is one installable capability, phrased for a
Linux-client black-box pass and tagged `@iq`:

| Feature file | Capability (standard) |
|---|---|
| [`LinuxServerDeployment.feature`](./Features/LinuxServerDeployment.feature) | Deployment + hardening: health, TLS pinning, no `Server` header, HTTP→HTTPS |
| [`EstEnrollment.feature`](./Features/EstEnrollment.feature) | RFC 7030 EST + RFC 9908 template retrieval + Basic auth, driven by `estclient` with independent `openssl` checks |
| [`AcmeIssuance.feature`](./Features/AcmeIssuance.feature) | RFC 8555 ACME end-to-end, driven by `acme.sh` and `certbot` |
| [`AuthorityInformation.feature`](./Features/AuthorityInformation.feature) | CDP, AIA OCSP/caIssuers, EST/ACME consistency, and profile-fixed EKUs/policies, inspected by `openssl` |
| [`CaaEnforcement.feature`](./Features/CaaEnforcement.feature) | RFC 8659/8657 CAA, observed through the ACME path (fail-closed) |
| [`DeviceAttestation.feature`](./Features/DeviceAttestation.feature) | `device-attest-01` advertisement + fail-closed |
| [`OcspResponder.feature`](./Features/OcspResponder.feature) | RFC 6960 OCSP, driven by `openssl ocsp` |
| [`CrlRevocation.feature`](./Features/CrlRevocation.feature) | RFC 5280 CRL + revocation, driven by `openssl crl` / authenticated revocation |
| [`CertificateInventory.feature`](./Features/CertificateInventory.feature) | CA inventory + certificate retrieval |
| [`ProfileIssuance.feature`](./Features/ProfileIssuance.feature) | Profile-fixed cert content (policies/KU/EKU), verified by `openssl x509 -text` |
| [`McpServer.feature`](./Features/McpServer.feature) | MCP stdio server: tool listing, read-only tools, destructive-gate |
| [`OpenTelemetry.feature`](./Features/OpenTelemetry.feature) | OTel metrics/traces actually emitted after client-driven traffic |
| [`OpenCertCli.feature`](./Features/OpenCertCli.feature) | The `opencert` CLI running as a Linux binary against the live server |

## Conventions

- Tags: `@iq` on every feature; `@blackbox`, `@linux-client`, `@hardened` where
  relevant, so a run can select "the install-qualification slice".
- Endpoints and behaviour mirror those documented in
  [`docs/standards.md`](../../docs/standards.md) and
  [`docs/documentation.md`](../../docs/documentation.md); RFC numbers are the
  source of truth, as they are for the conformance suite.
- Where a scenario's outcome depends on the hardened server posture, the *given*
  states the posture so the scenario reads as a self-contained acceptance test.
