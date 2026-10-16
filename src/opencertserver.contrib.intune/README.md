# opencertserver.contrib.intune

Intune challenge validation and revocation sync for the OpenCertServer SCEP
server. Optional: the SCEP server works with a shared secret without it.

## What it does

**Challenge validation.** Intune hands every managed device a challenge and
checks it on request. `IntuneChallengeValidator` sends each PKCSReq
(transaction id and the whole CSR) to Intune's SCEP validation service
(`ScepRequestValidationFEService`, discovered through Microsoft Graph) and
lets the CA issue only when Intune says yes. Intune refusing, unreachable or
throttling (429) all mean the request is denied - nothing is issued on a
hunch. After issuing, Intune receives the success notification (thumbprint,
serial number, expiry); if the CA refuses after Intune allowed, the failure
notification. A renewal signed with the previous certificate passes without
Intune, as with the shared secret.

**Revocation sync.** Intune never tells the CA when a user is disabled or a
device is retired. `IntuneRevocationSync` walks the CA inventory and asks
Graph about the user (UPN from the SAN), the Intune device
(`IntuneDeviceId://` URI) and the Entra device (GUID common name), and
revokes what is gone or disabled (reason `cessationOfOperation`). Graph
unreachable or throttled means *unknown*, and unknown is never revoked. A
run aborts when it would revoke more than `MaxRevocationsPerSync` (25).
It is an operation, not a scheduler: `POST /scep/intune/sync?dryRun=true|false`
returns a report, 409 while a run is in progress; the endpoint requires the
authorization policy `scep_intune_sync`.

## Configuration (`Scep:Intune`)

| Key | Meaning |
|---|---|
| `TenantId` | Entra tenant (GUID or domain) |
| `ClientId` | App registration with the Intune permission `scep_challenge_provider` and, for the sync, Graph `User.Read.All`, `Device.Read.All`, `DeviceManagementManagedDevices.Read.All` (application permissions) |
| `ClientCertificateFile` + `ClientCertificateKeyFile` | The app's certificate credential (PEM): a signed client assertion (RFC 7523), only the public half goes to Entra - preferred |
| `ClientSecret` or `ClientSecretFile` | Alternatively the secret, or a file holding it (first line) |
| `CallerInfo` | Shown in Intune's logs (default `OpenCertServer`) |
| `LoginBase`, `GraphBase`, `IntuneResource` | Override for national clouds |
| `ValidationEndpoint` | Skip Graph discovery (tests) |
| `Timeout` | Per request (default 30 s) |
| `MaxRevocationsPerSync` | Guard for the sync (default 25) |

As environment variables: `Scep__Intune__TenantId` and so on.

## Wiring

```csharp
services.AddIntune(configuration);          // or AddIntune(new IntuneOptions { ... })
services.AddScepServer(new ScepServerOptions { RaCertificate = ra });
services.AddAuthorization(o => o.AddPolicy(ContribIntuneExtensions.SyncPolicyName, p => p.RequireRole("ca_admin")));
...
app.MapScepServer();
app.MapIntuneSync();                        // POST /scep/intune/sync
```

`certserver` does this when `Scep:Intune` is configured; the sync policy
there requires the `ca_admin` role.

## Tests

`tests/opencertserver.contrib.intune.tests`: BDD scenarios against an in-process
fake of Entra, Graph and the validation service (`FakeIntune`) - allowed,
refused, unreachable, throttled, notifications, discovery and token reuse,
renewal without Intune; for the sync: disabled and deleted users, retired
Intune devices, disabled Entra devices, Graph throttled or down (nothing
revoked), dry run, the revocation limit, a second run while one is running,
and the endpoint's policy. What a fake cannot say about the real service is
left to an end-to-end test against a real tenant.
