# opencertserver.build

The build and packaging automation for OpenCertServer, implemented as a
[Cake](https://cakebuild.net/) application on the [Frosting](https://cakebuild.net/docs/overview/frosting)
framework. Each task is a `FrostingTask` and is invoked from the command line; tasks declare
their ordering with `IsDependentOn`, so a single entry point runs the whole pipeline.

## Tasks

| Task | Runs after | Purpose |
|---|---|---|
| `Version` | — | Derives the build version with `GitVersion` (`GitVersion.Tool`). |
| `Clean` | `Version` | Removes build artifacts. |
| `Restore-Nuget-Packages` | `Clean` | `dotnet restore`. |
| `Build` | `Restore-Nuget-Packages` | Compiles the solution. |
| `Tests` | `Build` | Runs the test suites. |
| `Pack` | `Tests` | Produces the NuGet packages. |
| `Linux-Docker-Build` | `Pack` | Builds the Linux Docker image (`Cake.Docker`). |
| `CLI Publish` | `Linux-Docker-Build` | Publishes the `opencert` CLI as trimmed, self-contained single-file binaries. |
| `Default` | `CLI Publish` | Deliberately empty; because it depends on the whole chain above, running it (or running with no task name) executes `Version → … → CLI Publish`. |

## Run

From the repository root, Frosting runs a task by its name as the last argument:

```sh
# Full pipeline (version, clean, restore, build, test, pack, docker, CLI publish):
dotnet run --project build/opencertserver.build -- Default

# Or run a single task (its dependencies run first):
dotnet run --project build/opencertserver.build -- Pack
dotnet run --project build/opencertserver.build -- Tests
```

`CLI Publish` emits one binary per runtime to `artifacts/publish/cli/{runtime}/`
(`linux-musl-x64`, `linux-x64`, `linux-arm64`, `osx-arm64`, `win-x64`, `win-x86`,
`win-arm64`), each published trimmed and self-contained as a single file with compression.

## Dependencies

- `Cake.Frosting` — the task runner.
- `Cake.Docker` — the Linux Docker image build.
- `GitVersion.MsBuild` / the `GitVersion.Tool` (installed at host startup) — semantic versioning.
- `System.Security.Cryptography.Pkcs` — used by the packaging tasks.

The version is not hard-coded; it is read from Git history by `GitVersion`, so tag the
repository to control release versions.
