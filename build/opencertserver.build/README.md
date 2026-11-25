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
| `Linux-Docker-Build` | `Build` | Builds framework-qualified .NET 10 and 11 Linux Docker images (`Cake.Docker`). |
| `Appliance-Docker-Build` | `Pack` | Publishes each appliance role for .NET 10 and 11 and builds framework-tagged images. |
| `CLI Publish` | `Linux-Docker-Build` | Publishes the `opencert` CLI as trimmed, self-contained single-file binaries. |
| `Default` | `CLI Publish` | Runs the build, Linux image, and CLI publish chain. |

## Run

From the repository root, Frosting runs a task by its name as the last argument:

```sh
# Default pipeline (version, clean, restore, build, Docker, CLI publish):
dotnet run --project build/opencertserver.build -- Default

# Or run a single task (its dependencies run first):
dotnet run --project build/opencertserver.build -- Pack
dotnet run --project build/opencertserver.build -- Tests
```

`CLI Publish` emits one binary per runtime to `artifacts/publish/cli/{runtime}/`
(`linux-musl-x64`, `linux-x64`, `linux-arm64`, `osx-arm64`, `win-x64`, `win-x86`,
`win-arm64`), each published trimmed and self-contained as a single file with compression.

`Linux-Docker-Build` tags each image with `latest-<tfm>` and `<version>-<tfm>`.
For compatibility, the .NET 10 image also receives the unqualified `latest` and
`<version>` tags.

## Dependencies

- `Cake.Frosting` — the task runner.
- `Cake.Docker` — the Linux Docker image build.
- `GitVersion.MsBuild` / `GitVersion.Tool` — semantic versioning. Frosting installs
  the platform-specific .NET tool at host startup. The Version task uses GitVersion 7's
  `--output json --no-normalize` CLI and `VersionSourceDistance` output field.
- `System.Security.Cryptography.Pkcs` — used by the packaging tasks.

The version is not hard-coded; it is read from Git history by `GitVersion`, so tag the
repository to control release versions.
For a `beta/<name>` branch, the build version is `<name>-<VersionSourceDistance>`.
