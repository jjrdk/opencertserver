# AGENTS.md

## OpenCertServer: AI Agent Guidance

### Big Picture Architecture
- **OpenCertServer** is a modular certificate authority platform supporting EST (RFC 7030) and ACME (RFC 8555) protocols.
- Major components:
  - `src/opencertserver.certserver`: Main web app, hosts ACME, CA, and EST endpoints.
  - `src/opencertserver.acme.server`: ACME server implementation (certificate issuance, challenge handling).
  - `src/opencertserver.ca`: Core CA logic (issuance, validation, revocation).
  - `src/opencertserver.ca.server`: ASP.NET Core web server for CA endpoints (certificate issuance, management, authentication).
  - `src/opencertserver.est.server`: EST server implementation (secure certificate enrollment).
  - `src/CertesSlim`: Lightweight ACME client library.
  - `src/web`: Angular web UI for certificate management.
  - `src/opencertserver.lambda2`: AWS Lambda entry point for serverless deployment.
- Utility and abstraction projects (`ca.utils`, `acme.abstractions`, etc.) provide shared models and helpers.

### Service Boundaries & Data Flows
- ACME and EST endpoints are exposed via ASP.NET Core middleware; authentication is typically certificate-based or JWT.
- CA logic is centralized in `opencertserver.ca` and accessed by server components.
- Web UI interacts with backend via REST APIs (see `web/config.json`).
- Lambda entry points adapt the server for AWS API Gateway/ALB.

### Developer Workflows
- **Build:** Use `build.sh` (Mac/Linux) or `build.ps1` (Windows) in project root to compile and package all components.
- **Test:** Tests are located in `tests/` directories; run with standard .NET test tools.
  - **Web UI:**
    - See `web/README.md` for full setup, OIDC configuration, and build instructions.
  - **Deployment:**
    - Main server: Deploy `certserver` web app
    - Lambda: Use `lambda2` for AWS serverless (preferred) or `lambda` for legacy/alternative scenarios

### Project-Specific Conventions
- **Environment Variables:** Use double underscores (`__`) for hierarchical config (e.g., `RSA_PEM`, `WEB_KEY`).
- **Authentication:** Configure certificate authentication via `CertificateAuthenticationDefaults.AuthenticationScheme`.
- **Middleware Injection:** Add EST/ACME middleware in `Startup.Configure` (e.g., `app.UseEstServer()`, `app.UseAcmeClient()`).
- **Persistence:** ACME supports file, memory, or custom persistence for certificates and challenges (see `AddAcmeFileCertificatePersistence`, `AddAcmeMemoryChallengePersistence`).
- **Endpoints:**
  - EST: `/.well-known/est/cacerts`, `/.well-known/est/simpleenroll`, `/.well-known/est/simplereenroll`
  - ACME: Standard ACME endpoints for account, order, challenge

### Integration Points & Dependencies
- **CertesSlim**: Used for ACME protocol operations
- **CA Utilities**: Shared X.509/PKI helpers in `ca.utils`
- **External:** DnsClient, Amazon.Lambda.AspNetCoreServer, Angular Material

### Key Files & Directories
  - `README.md` (root): High-level overview, build instructions
  - `src/opencertserver.certserver/`: Main entry point
  - `src/opencertserver.ca.server/`: CA web server endpoints
  - `src/web/`: Angular UI, OIDC/API config
  - `build/`: Build scripts and context
  - `build/opencertserver.build/`: Build automation and context
  - `tests/`: Test suites for all major components

---
For further details, consult component-specific README files and configuration examples. Follow established patterns for authentication, middleware, and persistence. Use build scripts for packaging and deployment.

