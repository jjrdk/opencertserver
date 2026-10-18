# Build runtime image
# PLATFORM/RID default to the published amd64 musl build; the IQ test harness overrides both to run
# the image natively on the Docker host's architecture (e.g. linux/arm64 + linux-musl-arm64).
ARG PLATFORM=linux/amd64
FROM --platform=${PLATFORM} mcr.microsoft.com/dotnet/runtime-deps:10.0-alpine
ARG RID=linux-musl-x64
ENV ACCEPT_EULA=Y
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=true
# The hardened installation profile is the default in the published image; it embeds the CDP / AIA /
# OCSP responder URLs, enables external account binding and OpenTelemetry export over OTLP, and
# enforces the device-attest-01 fail-closed posture when no trust roots are mounted.
ENV ASPNETCORE_ENVIRONMENT=Hardened
RUN addgroup -S certificateservergroup && adduser -S certificateserveruser -G certificateservergroup
USER certificateserveruser
COPY artifacts/publish/server/${RID}/ app/
WORKDIR /app
EXPOSE 6000 6001
ENTRYPOINT ["./opencertserver.certserver"]
