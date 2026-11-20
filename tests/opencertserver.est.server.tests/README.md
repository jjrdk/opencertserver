# opencertserver.est.server.tests

Reqnroll BDD coverage for the
[`opencertserver.est.server`](../../src/opencertserver.est.server/README.md) EST (RFC 7030)
endpoints. The HTTP layer is exercised in-process through `TestMessageHandler` and
`TestCsrAttributesLoader` (no live server, no containers).

## Feature suites

- `Features/EstServer.feature` — the core EST endpoints (`cacerts`, `csrattrs`,
  `simpleenroll`, `simplereenroll`, `serverkeygen`).
- `Features/ReEnrollmentProfiles.feature` — re-enrollment and per-profile behavior.
- `Features/EstBasicAuthentication.feature` — basic-auth EST clients.
- `Features/EstClientTls.feature` — client-certificate (mTLS) EST authentication.
- `Features/CaProfilePolicies.feature` — CA profile selection and policies behind issuance.

## Run

```sh
dotnet test --project tests/opencertserver.est.server.tests
```

No containers are required.
