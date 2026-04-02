# opencertserver.est.server

This project provides the EST (Enrollment over Secure Transport, RFC 7030) server implementation for OpenCertServer. It exposes endpoints for secure certificate enrollment and management, supporting both certificate and JWT authentication.

## Functionality
- Implements EST server endpoints for certificate enrollment
- Supports secure authentication and certificate issuance
- Publishes EST CA certificate bundles through `/.well-known/est/cacerts`
- Supports EST root key rollover publication for clients that need to transition to a new CA key

## Dependencies
- Microsoft.AspNetCore.Authentication.Certificate
- Microsoft.AspNetCore.Authentication.JwtBearer
- Microsoft.Extensions.DependencyInjection.Abstractions
- opencertserver.ca.utils (certificate utilities)

## Key rollover

OpenCertServer separates the **active issuing chain** from the **EST-published CA bundle**:

- `CaProfile.CertificateChain` is the active CA chain used for signing new certificates and validating the current CA configuration.
- `CaProfile.PublishedCertificateChain` is the certificate set returned from `/.well-known/est/cacerts`.

If `PublishedCertificateChain` is empty, the EST server falls back to `CertificateChain`.

### How rollover works

EST key rollover is a publication concern, not an issuance-mode switch.

When you rotate a root or issuing CA key:

1. the **new** CA certificate and private key become the active signing material in `CertificateChain`;
2. the EST server continues issuing certificates from that active CA; and
3. the EST `/cacerts` response publishes a larger transition bundle so clients can learn the new trust anchor safely.

When rollover is configured, the EST `/cacerts` response can contain:

- the current root CA certificate;
- `OldWithOld` — the previous self-signed root certificate;
- `OldWithNew` — the previous root public key signed by the current root key; and
- `NewWithOld` — the current root public key signed by the previous root key.

That bundle lets EST clients fetch the current trust anchor together with the certificates needed to bridge trust during a root key transition.

### Using rollover in code

If you host the EST server as a library, configure rollover by keeping the active CA in `CertificateChain` and publishing the transition bundle through `PublishedCertificateChain`:

- `CertificateChain`: current issuing CA only
- `PublishedCertificateChain`: current issuing CA + rollover certificates (`OldWithOld`, `OldWithNew`, `NewWithOld`)

The built-in self-signed CA helpers already create a rollover publication bundle automatically, so development and test environments expose rollover certificates from `/cacerts` without changing the active issuing key.

### Using rollover with the file-backed `opencertserver.certserver` host

The executable server now supports publishing a rollover bundle for file-backed CA profiles without requiring application code changes.

For each profile, keep the active certificate/key on the existing options and provide an additional PEM bundle for what EST should publish from `/cacerts`:

- RSA profile:
  - active CA certificate: `--rsa`
  - active CA private key: `--rsa-key`
  - published EST bundle: `--rsa-published`
- ECDSA profile:
  - active CA certificate: `--ec`
  - active CA private key: `--ec-key`
  - published EST bundle: `--ec-published`

The published PEM bundle should contain the certificates you want clients to receive during rollover, typically the current CA certificate plus `OldWithOld`, `OldWithNew`, and `NewWithOld`. If the active CA certificate is missing from the published bundle, the host adds it automatically so `/cacerts` always includes the current trust anchor.

You can also supply the published bundle path through environment variables loaded by the host configuration:

- `RSA__PublishedPem`
- `ECDSA__PublishedPem`

Example:

```zsh
dotnet run --project src/opencertserver.certserver -- \
  --rsa /path/to/current-rsa-ca.crt \
  --rsa-key /path/to/current-rsa-ca.key \
  --rsa-published /path/to/rsa-est-rollover.pem \
  --ec /path/to/current-ecdsa-ca.crt \
  --ec-key /path/to/current-ecdsa-ca.key \
  --ec-published /path/to/ecdsa-est-rollover.pem
```

### Recommended rollover process

1. Generate the new CA key pair and new CA certificate.
2. Switch `CertificateChain` to the **new active issuing CA**.
3. Publish a rollover bundle through `PublishedCertificateChain` or the `--*-published` host options.
4. Leave the rollover bundle available long enough for EST clients to refresh trust and accept the new root.
5. After the transition window, remove the old rollover certificates from the published bundle and keep publishing only the steady-state CA chain.

Use this project to deploy an EST-compliant certificate authority server.
