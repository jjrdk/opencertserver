# Build runtime image
# PLATFORM/RID default to the published amd64 musl build; the IQ test harness overrides them and
# the .NET version/target framework to run each target natively on the Docker host's architecture.
ARG PLATFORM=linux/amd64
ARG DOTNET_VERSION=10.0
FROM --platform=${PLATFORM} mcr.microsoft.com/dotnet/runtime-deps:${DOTNET_VERSION}-alpine
ARG RID=linux-musl-x64
ARG TFM=net10.0
ENV ACCEPT_EULA=Y
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=true
# The hardened installation profile is the default in the published image; it embeds the CDP / AIA /
# OCSP responder URLs, enables external account binding and OpenTelemetry export over OTLP, and
# enforces the device-attest-01 fail-closed posture when no trust roots are mounted.
ENV ASPNETCORE_ENVIRONMENT=Hardened
RUN addgroup -S certificateservergroup && adduser -S certificateserveruser -G certificateservergroup
RUN mkdir -p /var/lib/opencertserver \
    && chown certificateserveruser:certificateservergroup /var/lib/opencertserver
USER certificateserveruser
COPY artifacts/publish/${TFM}/server/${RID}/ app/
WORKDIR /app
EXPOSE 6000 6001
VOLUME ["/var/lib/opencertserver"]
ENTRYPOINT ["./opencertserver.certserver"]
