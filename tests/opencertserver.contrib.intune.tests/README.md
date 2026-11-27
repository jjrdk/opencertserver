# opencertserver.contrib.intune.tests

Reqnroll BDD coverage for the
[`opencertserver.contrib.intune`](../../src/opencertserver.contrib.intune/README.md) SCEP
challenge validator and revocation sync. Entra / Graph and the SCEP validation service are
replaced by an in-process `FakeIntune` (`FakeIntune.cs`), and the HTTP surface is driven
through `TestHostBuilder`, so no real tenant is needed.

## Feature suites

- `Features/IntuneChallenge.feature` — challenge validation: allowed, refused, unreachable,
  throttled (429), the success/failure notifications, Graph discovery, token reuse, and a
  renewal that passes without Intune.
- `Features/IntuneRevocationSync.feature` — the revocation sync: disabled and deleted users,
  retired Intune devices, disabled Entra devices, Graph throttled or down (nothing revoked),
  a dry run, the `MaxRevocationsPerSync` limit, a second run while one is in progress, and
  the `scep_intune_sync` endpoint policy.
- `Features/IntuneDeviceName.feature` — `IIntuneClient.GetManagedDeviceName` resolving the
  human-readable device name (null when the device no longer exists).

What a fake cannot say about the real service is left to an end-to-end test against a real
tenant.

## Run

```sh
dotnet test --project tests/opencertserver.contrib.intune.tests
```

No containers are required.
