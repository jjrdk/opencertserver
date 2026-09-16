# OpenCertServer ACME YARP Tests

This project exercises the YARP integration of `opencertserver.acme.aspnetclient` through Reqnroll BDD
scenarios. The feature files document the behavior of per-route ACME certificate issuance, Kestrel SNI
selection, backward compatibility, and the renewal lifecycle; the step definitions drive the real
`AcmeRenewalService`, `KestrelOptionsSetup`, and `AddAcmeRoutesConfigFilter` types without a live ACME
server.

## Feature suites

- `Features/ChallengeApproval.feature` - HTTP-01 challenge approval served per-route via the middleware.
- `Features/BackwardCompatibility.feature` - untagged single-listener usage falls back to the default route.
- `Features/KestrelSniSelection.feature` - per-host leaf selection and hot-renew pickup via SNI.
- `Features/PerRouteRegistration.feature` - one ACME descriptor per ACME-enabled YARP route.
- `Features/PerRouteIssuance.feature` - two routes place two distinct ACME orders and serve two separate leaves.
- `Features/RenewalLifecycle.feature` - per-route renewal, failure isolation, and stop semantics.

Step definitions live under `StepDefinitions/` and the shared test doubles under the project root
(`InMemoryAcmeClient`, `RoutingCertificateProvider`, `RecordingLifecycleHook`, `SelfSignedCertificate`,
`TestAcmeOptions`, `TestFixture`, `TestRenewalService`).

## Dependencies

- `../../src/opencertserver.acme.yarp/opencertserver.acme.yarp.csproj`
- `../../src/opencertserver.acme.aspnetclient/opencertserver.acme.aspnetclient.csproj`
- `../../src/opencertserver.acme.abstractions/opencertserver.acme.abstractions.csproj`
- `Microsoft.AspNetCore.TestHost`, `Microsoft.Extensions.DependencyInjection`, `NSubstitute`,
  `Reqnroll.xUnit.v3`, and `xunit.v3.mtp-v2`
