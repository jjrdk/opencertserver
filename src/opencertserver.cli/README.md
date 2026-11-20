# opencertserver.cli

The `opencert` command-line tool. It wraps the OpenCertServer libraries to cover the
certificate operations used most during development and administration: key
generation, CSR creation, local signing, certificate inspection, and EST
enrollment against a running server. The executable assembly is named `opencert`.

## Commands

| Command | Purpose |
|---|---|
| `generate-keys` | Create an RSA or ECDSA key pair and write it as PEM files. |
| `create-csr` | Build a CSR from a private key, prompting for the subject fields. |
| `create-csr-from-keys` | Build a CSR from a matching public/private key pair. |
| `sign-csr` | Sign a CSR locally with a CA key and certificate. |
| `print-cert` | Print a certificate's details (PEM or DER). |
| `est-enroll` | Generate a CSR and enroll it over EST. |
| `est-reenroll` | Re-enroll (renew) an existing certificate over EST. |
| `est-server-certificates` | Fetch the EST server's published CA bundle. |
| `hash-password` | Hash a password (PBKDF2) for EST Basic authentication, read from stdin. |

Run `opencert --help` or `opencert <command> --help` for the full option list of
each command.

## Build and run

```sh
dotnet run --project src/opencertserver.cli -- <command> [options]
```

The tool targets the repository's framework and builds for the supported runtimes
(see the `opencertserver.cli.csproj` runtime targets).

## Examples

### Generate a key pair

```sh
opencert generate-keys --algorithm ecdsa --ecdsa-curve nistP384 --out ./keys/server
# writes ./keys/server-private.pem and ./keys/server-public.pem
opencert generate-keys --algorithm rsa --rsa-key-size 4096 --out ./keys/ca
```

### Create a CSR

Subject fields (`--C`, `--ST`, `--L`, `--O`, `--OU`, `--CN`, `--E`, `--san`,
`--key-usage`, `--eku`, `--basic-ca`, `--basic-path-len`, `--subject`,
`--rsa-padding`) are taken from the command line; when none are given the command
prompts for them. `--san` is a comma-separated list (IP addresses are detected
automatically); `--key-usage` and `--eku` accept comma-separated flags.

```sh
opencert create-csr --private-key ./keys/server-private.pem \
  --CN service.example.com --O "Example Corp" --san service.example.com,www.example.com \
  --key-usage digitalSignature,keyEncipherment --eku serverAuth \
  --out ./keys/server.csr.pem
```

`create-csr-from-keys` is the same, but also takes a `--public-key` (the matching
public key or a certificate) and verifies the pair matches:

```sh
opencert create-csr-from-keys --private-key ./keys/server-private.pem \
  --public-key ./keys/server-public.pem --CN service.example.com
```

### Sign a CSR locally

```sh
opencert sign-csr --csr ./keys/server.csr.pem \
  --ca-key ./keys/ca-private.pem --ca-cert ./keys/ca.crt --out ./keys/server.crt
```

### Inspect a certificate

```sh
opencert print-cert --cert ./keys/server.crt
```

### EST enrollment

The EST subcommands talk to a running
[`opencertserver.est.server`](../opencertserver.est.server/README.md). The server
URL must be HTTPS. Authentication is an `--auth` header value (e.g.
`'Bearer <token>'`) or Basic credentials via `--user 'name:password'`
(RFC 7030 §3.2.3); mTLS uses `--client-cert` (a PFX/PKCS#12 with a private key).
Trust is controlled with `--ta-mode` (`implicit` default, `explicit`,
`explicit-then-implicit`) and one or more `--est-ca` anchor files.

```sh
# Enroll
opencert est-enroll --url https://est.example.com --profile rsa \
  --private-key ./keys/server-private.pem --out ./keys/enrolled.pem \
  --CN service.example.com --san service.example.com

# Renew (the renewal key must match the existing certificate's public key)
opencert est-reenroll --url https://est.example.com --profile rsa \
  --private-key ./keys/renewal-private.pem --cert ./keys/enrolled.pem \
  --out ./keys/reenrolled.pem

# Fetch the server's CA bundle
opencert est-server-certificates --url https://est.example.com
```

On success each EST command writes the returned PEM chain to `--out`
(defaults: `est-cert.pem`, `reenrolled.pem`). A server failure is printed and the
command exits non-zero.

### Hash a password for EST Basic auth

The password is read from standard input, never the command line, so it does not
appear in the process list or shell history:

```sh
printf '%s' 'secret' | opencert hash-password --iterations 100000
```

The output is the hash for `Est:BasicAuth:Users` in the EST server configuration.

## Dependencies

- `System.CommandLine` — the command model and argument parsing.
- `opencertserver.ca.utils` — X.509 / PKI helpers (`PrintCertificate`, `PasswordHash`).
- `opencertserver.ca` — core CA logic used by `sign-csr`.
- `opencertserver.est.client` — the EST enrollment / re-enrollment / bootstrap flows.

This project is the public-facing command-line surface over the lower-level CA and
EST libraries.
