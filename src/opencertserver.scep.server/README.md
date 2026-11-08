# opencertserver.scep.server

The SCEP (RFC 8894) protocol layer: `ScepServerOptions`, the `MapScepServer()` /
`MapIntuneSync()` extensions, `ScepHandler`, and the shared-secret / Intune challenge
validators. This project is the **library**; the standalone host that runs it against a
backing CA is [`opencertserver.scep`](../opencertserver.scep/README.md).

`MapScepServer()` maps `/scep` and the Windows `/scep/pkiclient.exe` form, GET and
POST, plus `/scep/{profileName}`. `MapIntuneSync()` (from
`opencertserver.contrib.intune`) maps `POST /scep/intune/sync`.

See [`docs/architecture-separation.md`](../../docs/architecture-separation.md) for the
backing-CA topology and the SCEP composition gate.
