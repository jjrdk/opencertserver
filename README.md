# OpenCertServer

OpenCertServer is a modular, ASP.NET Core **certificate authority** platform. It combines a full
certificate authority (issue, enroll, revoke) with the HTTP-based enrollment protocols that let
machines and applications obtain X.509 certificates without human intervention, plus the status and
revocation infrastructure (OCSP/CRL) that makes those certificates trustworthy.

It talks in the open standards that already run the Web PKI:

| Protocol / standard | What it is for | Status |
|---|---|---|
| **EST** – Enrollment over Secure Transport ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030), [8951](https://www.rfc-editor.org/rfc/rfc8951), [9908](https://www.rfc-editor.org/rfc/rfc9908)) | Enroll and re-enroll certificates over TLS with a client certificate or JWT. | Implemented |
| **ACME** – Automated Certificate Management Environment ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555), [8657](https://www.rfc-editor.org/rfc/rfc8657), [8659](https://www.rfc-editor.org/rfc/rfc8659)) | Issue certificates for domain names via `http-01` / `dns-01` challenges. | Implemented |
| **Device attestation** – `device-attest-01` ACME challenge ([FIDO](https://fidoalliance.org/) style, TPM/Apple SE backed) | Issue certificates to hardware-backed devices instead of domains. | Implemented |
| **OCSP** ([RFC 6960](https://www.rfc-editor.org/rfc/rfc6960)) | Online "is this certificate still valid?" status responses. | Implemented |
| **CRL** ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)) | Certificate Revocation Lists and authenticated revocation. | Implemented |
| **MCP** – Model Context Protocol server | Expose CA operations as tools for AI agents (stdio). | Implemented |

The ACME implementation is derived from the
[PKISharp ACME Server](https://github.com/PKISharp/ACME-Server) and
[FluffySpoon EncryptWeMust](https://github.com/ffMathy/FluffySpoon.AspNet.EncryptWeMust) projects,
both MIT licensed. See [Implemented standards](docs/standards.md) for a standard-by-standard
walkthrough with the tests that prove each behaviour.

> **New here?** Start with [Getting started](docs/getting-started.md) — a five-minute walk that runs
> a self-signed CA and enrolls a certificate. Then browse the full
> [Documentation index](docs/documentation.md).

---

## What OpenCertServer does

* **Acts as a CA.** Register one or more CA *profiles* (RSA and/or ECDSA) and issue, renew, and revoke
  X.509 certificates. Profiles can be self-signed at startup or supplied as PEM files.
* **Speaks three enrollment protocols.** EST for certificate/JWT-based enrollment, ACME for
  domain-based issuance, and device attestation for hardware-backed identity.
* **Answers revocation.** A built-in OCSP responder and CRL publication let relying parties check
  status; revocation is authenticated so only the key holder (or the CA) can revoke.
* **Sits in front of YARP.** `opencertserver.acme.yarp` auto-provisions one ACME certificate per
  YARP route on a single HTTPS listener, selected by SNI.
* **Is scriptable and automatable.** A cross-platform `opencert` CLI and an
  [MCP server](docs/getting-started.md#8-mcp-server-expose-the-ca-to-an-ai-agent) put every CA operation on the command line or behind
  a tool interface for AI agents.

## Solution layout

| Project | Responsibility |
|---|---|
| `opencertserver.certserver` | The runnable web app. Wires CA + EST + ACME + authentication together and listens on HTTPS. |
| `opencertserver.ca` | Core CA logic: issue, validate, revoke; certificate chain and CRL building. |
| `opencertserver.ca.server` | CA HTTP endpoints (`/ca/*`): CSR, inventory, revoke, CRL, OCSP, certificate retrieval. |
| `opencertserver.est.server` | EST server endpoints and the CSR-template (`/csrattrs`, RFC 9908) machinery. |
| `opencertserver.est.client` | EST client for enrolling/re-enrolling certificates from your own code. |
| `opencertserver.acme.server` | ACME server: directory, accounts, orders, challenges, revocation (RFC 8555). |
| `CertesSlim` | Lightweight ACME client protocol library (JWS, directory, order lifecycle). |
| `opencertserver.acme.aspNetClient` | ASP.NET Core ACME client, challenge middleware, and a renewal service. |
| `opencertserver.acme.yarp` | Per-route ACME provisioning for a YARP reverse proxy. |
| `opencertserver.mcp` | Model Context Protocol server exposing CA tools over stdio. |
| `opencertserver.attestation` | Hardware attestation layer (AMD SEV-SNP, Intel SGX, Apple Secure Element) for device-attest. |
| `opencertserver.tpm` / `opencertserver.tss.net` | TPM key provisioning so CA private keys can stay inside a TPM. |
| `opencertserver.cli` | The `opencert` command-line tool (keys, CSRs, EST enroll/reenroll). |
| `web` | Angular UI for certificate management. |

Components are also published as NuGet packages, so you can embed the EST, ACME, or CA server in your
own ASP.NET Core host. See [Getting started → Embedding the server](docs/getting-started.md#6-embedding-the-server-in-your-own-app).

---

## Documentation

Pick the page that matches what you want to do:

| I want to… | Start here |
|---|---|
| Run a CA in five minutes and enroll a certificate | [Getting started](docs/getting-started.md) |
| See every standard OpenCertServer implements, with its tests | [Implemented standards](docs/standards.md) |
| Use the `opencert` CLI (generate keys, CSRs, EST enroll) | [Getting started → CLI](docs/getting-started.md#4-use-the-opencert-cli) |
| Use the EST / ACME client libraries from code | [Getting started → Client libraries](docs/getting-started.md#5-use-the-client-libraries-from-code) |
| Embed the EST/ACME/CA server in my own app | [Getting started → Embedding](docs/getting-started.md#6-embedding-the-server-in-your-own-app) |
| Auto-issue certificates for a YARP reverse proxy | [opencertserver.acme.yarp](src/opencertserver.acme.yarp/README.md) |
| Expose the CA to an AI agent over MCP | [opencertserver.mcp](src/opencertserver.mcp/README.md) |
| Read the endpoint reference (CA / EST / ACME / OCSP / CRL) | [Documentation index](docs/documentation.md) |
| Read the trust model / operational policy | [Certificate Policy](docs/opencertserver_cp.md) · [Certification Practice Statement](docs/opencertserver_cps.md) |
| Run in Docker / Kubernetes | [Docker](Docker.md) |
| See the telemetry (metrics/traces) exposed | [OpenTelemetry metrics & traces](OpenTelemetryMetricsTraces.md) |
| Report a vulnerability | [Security policy](SECURITY.md) |

---

## Building the project

Run the build script from the repository root to compile and package every component:

```sh
# macOS / Linux
./build.sh

# Windows
./build.ps1
```

This produces NuGet packages and a self-contained server publish under `artifacts/`.
The `certserver` application takes all of its configuration from command-line arguments (with
environment variables and `appsettings.json` as fall-through) — there are no required environment
variables. The two startup modes (self-signed CA vs. existing PEM CA) are covered in
[Getting started → Running the server](docs/getting-started.md#2-run-the-certserver).

---

## License

The project is licensed under the [MIT license](LICENSE).

## Contributions

All contributions are appreciated. Please provide them as an issue with an accompanying pull request.
The best way to get a contribution adopted is to make it easy to pull into the code base — a failing
test in the relevant feature project is the ideal reproduction. Open source projects are only as good
as their tests, so please respect the [BDD/Reqnroll](https://reqnroll.net/) style used throughout
`tests/` and add scenarios that lock in the behaviour you change.
