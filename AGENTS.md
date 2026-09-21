# AGENTS.md

## OpenCertServer: AI Agent Guidance

### Documentation layout

| Document | Purpose |
|---|---|
| `README.md` | Project overview and quick-start entry point. |
| `docs/getting-started.md` | Step-by-step how-to: build, run, enroll via CLI or client libraries, embed the server, use MCP. |
| `docs/standards.md` | Every implemented standard (RFC 7030, 8555, CAA, OCSP, CRL, device attestation, etc.) with the test that proves each claim. |
| `docs/documentation.md` | HTTP endpoint reference and configuration guide; the hub that links the other docs. |
| `docs/opencertserver_cp.md` / `docs/opencertserver_cps.md` | Certificate Policy and Certification Practice Statement. |

When adding or changing features, update the relevant docs in the same PR.

### Big Picture Architecture

- **OpenCertServer** is a modular CA platform supporting **EST (RFC 7030)**, **ACME (RFC 8555)**, device attestation (`device-attest-01`), CAA (RFC 8659/8657), OCSP (RFC 6960), and CRL (RFC 5280).
- Major components:

| Project | Role |
|---|---|
| `opencertserver.certserver` | Main web app; wires EST, ACME, and CA endpoints together. Minimal hosting (`WebApplication.CreateBuilder`). |
| `opencertserver.acme.server` | ACME server: issuance, challenges (`http-01`, `dns-01`, `device-attest-01`), CAA validation. |
| `opencertserver.acme.abstractions` | Shared abstractions (`IAccountService`, `IOrderService`, `IAttestationTrustProvider`, etc.). |
| `opencertserver.acme.aspnetclient` | ACME client for ASP.NET Core; auto-renewal, SNI, http-01 challenge middleware. |
| `opencertserver.acme.yarp` | Per-route ACME issuance on a YARP reverse proxy (one cert per `RouteConfig`, SNI-selected). |
| `opencertserver.ca` | Core CA logic: issuance, validation, revocation, OCSP, CRL. |
| `opencertserver.ca.server` | CA HTTP endpoints: `/ca/csr`, `/ca/revoke`, `/ca/inventory`, `/ca/crl`, `/ca/ocsp`, `/ca/certificate`. |
| `opencertserver.ca.utils` | Shared X.509/PKI helpers, CSR templates, OCSP/CRL builders, print helpers. |
| `opencertserver.est.server` | EST server: `cacerts`, `csrattrs` (RFC 9908), `simpleenroll`, `simplereenroll`, `serverkeygen`. |
| `opencertserver.est.client` | EST client; enrollment, re-enrollment, and bootstrap trust negotiation. |
| `opencertserver.attestation` | Attestation layer: AMD SEV-SNP, Intel SGX, Apple Secure Element behind `IAttestationTrustProvider`. |
| `OpenCertServer.Amd.Native` / `OpenCertServer.Sgx.Native` | Platform-specific native attestation runtimes. |
| `opencertserver.mcp` | MCP (Model Context Protocol) server exposing CA operations to AI agents over stdio. |
| `opencertserver.cli` | Cross-platform `opencert` CLI: `generate-keys`, `create-csr`, `create-csr-from-keys`, `sign-csr`, `est-enroll`, `est-reenroll`, `est-server-certificates`, `print-cert`. |
| `opencertserver.tpm` / `opencertserver.tss.net` / `TSS.Net.Managed` | TPM-backed CA key provisioning. |
| `opencertserver.lambda2` | AWS Lambda entry point (`opencertserver.lambda` for legacy). |
| `CertesSlim` | Lightweight ACME protocol library (JWS, order flow, challenge validation). |
| `src/web` | Angular management UI; see `src/web/README.md`. |
| `opencertserver.data` | Data persistence store abstractions. |

### Service Boundaries & Data Flows

- EST, ACME, and CA endpoints are exposed on the same host via `.NET minimal hosting` — `WebApplication.CreateBuilder` → `app.UseHttpsRedirection().UseAcmeServer().UseEstServer().UseCertificateAuthorityServer()`. See `docs/getting-started.md` §6 for a minimal wiring example.
- Authentication uses JWT bearer or mTLS (client certificate); `cacerts` and `csrattrs` are anonymous by default.
- CA logic is centralized in `opencertserver.ca` and consumed by `ca.server` and `acme.server` via DI.
- The `opencertserver.attestation` layer abstracts hardware trust roots so `acme.server` can accept device identities through `device-attest-01`.
- The `opencertserver.mcp` project wraps `ca.server` and `ca.utils` behind a stdio MCP transport for AI agent tool-calling.
- Web UI is the Angular app in `src/web`; see `src/web/README.md` for setup.

### Developer Workflows

- **Implement:** Follow established patterns for adding new endpoints or features:
        - Define models / interfaces in `ca.utils` or `acme.abstractions`.
        - Implement core logic in `ca.server` or `acme.server`.
        - Wire up via extension methods (`Add…Server` / `Use…Server`) in the server's `EstServerExtensions.cs` / `Extensions.cs`.
        - Register on the main app with `WebApplication.CreateBuilder` → `app.Use…Server()`.
        - Implement features with minimal changes to existing code, favouring composition and extension over modification. Use DI and functional patterns to keep components decoupled.
        - Add BDD tests: Reqnroll `.feature` files under `tests/<project>.tests/Features/` with step definitions that use existing fixtures. All tests must be in BDD style — no standalone unit tests (see zero-xunit policy).
        - Update the relevant doc: `docs/standards.md` for a new standard/protocol; `docs/getting-started.md` for a new how-to; `docs/documentation.md` for a new endpoint or config key.
- **Build:** Use `build.sh` (Mac/Linux) or `build.ps1` (Windows) at the repo root; or `dotnet build` / `dotnet test` per project.
- **Test:** Each project has a dedicated `tests/<project>.tests/` project. Run specific suites with:
        ```sh
   dotnet test tests/opencertserver.cli.tests/                 # CLI BDD
   dotnet test tests/opencertserver.acme.yarp.tests/           # YARP per-route ACME
   dotnet test tests/opencertserver.attestation.Tests/         # attestation backends
        ```
- **Web UI:** See `src/web/README.md` for Angular build, OIDC setup, and tenant config.
- **Deployment:**
        - Main server: `dotnet run --project src/opencertserver.certserver/`
        - Lambda: `opencertserver.lambda2` (preferred) or `opencertserver.lambda` (legacy).
        - CLI: `dotnet run --project src/opencertserver.cli/ -- <subcommand> …`

### Project-Specific Conventions

- **Config binding:** Use `IConfiguration` section binding and double-underscore hierarchy (e.g. `RSA__PEM=file:///…`). AcmeServer config: `configuration.GetSection("AcmeServer")`.
- **Authentication:** Register JWT and certificate schemes on the `IAuthenticationBuilder`: `.AddJwtBearer().AddCertificate().AddCertificateCache(options => { … })`. EST authorize via per-endpoint policies (`ConfigurePolicy()` — requires JWT or cert); `cacerts` / `csrattrs` are `AllowAnonymous()`.
- **Middleware/extension wiring:** No `Startup` class. Use `WebApplication.CreateBuilder(args)` → `builder.Services.Add…()` → `builder.Build()` → `app.Use…Server()`.
- **Persistence strategies:** Pluggable via `AddAcmeFileCertificatePersistence`, `AddAcmeFileChallengePersistence`, `AddAcmeInMemoryCertificatesPersistence`, `AddAcmeMemoryChallengePersistence`, `AddAcmeCertificateStorePersistence` (OS X.509 store), and custom delegates.
- **EstClient:** Constructor requires HTTPS (`estHost.Scheme` must be `https`); `Enroll`/`ReEnroll` return `(string? error, X509Certificate2Collection? certs)`. `ServerCertificates()` returns a `X509Certificate2Collection`.
- **CLI (`opencert`):** Subcommands use short options for subject fields: `--C` (country), `--ST` (state), `--L` (locality), `--O` (org), `--OU` (org unit), `--CN` (common name), `--E` (email), `--san` (SANs, comma-separated), `--key-usage`, `--eku`, `--basic-ca`, `--rsa-padding`. `est-enroll` / `est-reenroll` additionally accept `--url`, `--auth` (JWT), `--client-cert` (mTLS), `--est-ca`, `--ta-mode`.

### Integration Points & Dependencies

| Dependency | Used by | Purpose |
|---|---|---|
| `CertesSlim` | `acme.server`, `acme.aspnetclient`, `est.client` | JWS signing, order/challenge protocol operations |
| `ca.utils` | All CA-dependent projects | CSR/PKI helpers, templates, OCSP/CRL builders, `PrintCertificate()` |
| `ModelContextProtocol` | `opencertserver.mcp` | MCP server SDK (stdio transport, `[McpServerTool]` discovery) |
| `Microsoft.Extensions.DependencyInjection` | All server projects | DI container and extension methods |
| `Yarp.ReverseProxy` | `acme.yarp`, `yarp.server` | Reverse-proxy routing; per-route ACME |
| `DnsClientX` | `acme.server` | `dns-01` challenge validation |
| `Amazon.Lambda.AspNetCoreServer` | `opencertserver.lambda2` | AWS Lambda + ASP.NET Core adapter |
| `angular-material` / `@angular/core` | `src/web` | Management UI |
| `OpenCertServer.Amd.Native` / `Sgx.Native` | `attestation` | Platform-specific native attestation runtimes |

### Key Docs & Entry Points

| File | Purpose |
|---|---|
| `README.md` | Project overview page — quick-start + links into the documentation set |
| `docs/getting-started.md` | Step-by-step build / run / enrol / CLI / embed / MCP how-to with tested code samples |
| `docs/standards.md` | All implemented standards with RFC links, endpoint tables, and per-standard test references |
| `docs/documentation.md` | Full HTTP endpoint + configuration reference; documentation hub |
| `docs/opencertserver_cp.md` / `docs/opencertserver_cps.md` | Certificate Policy / Certification Practice Statement |
| `src/opencertserver.certserver/Program.cs` | Main entry point — minimal host wiring for all three servers |
| `src/opencertserver.certserver/appsettings.json` | Config schema examples (ACME, EST, JWT, OCSP, CRL) |
| `src/opencertserver.cli/Program*.cs` | CLI subcommand implementations (partial `Program` class, one file per subcommand) |
| `src/opencertserver.acme.yarp/README.md` | YARP per-route ACME — full sample and SNI wiring |
| `src/opencertserver.mcp/README.md` | MCP server — tool list and config |
| `src/opencertserver.attestation/README.md` | Attestation backends and native package layout |

---
Follow established conventions and extension patterns for authentication, persistence, middleware, and config.
Use `docs/standards.md` and `docs/documentation.md` as the source of truth for endpoint behaviour;
use `docs/getting-started.md` for step-by-step setup;
use build scripts for packaging and deployment.
When adding or changing features, update the relevant docs in the same PR.
