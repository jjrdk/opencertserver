#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/runtime-deps:8.0-alpine AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["src/opencertserver.certserver/opencertserver.certserver.csproj", "src/opencertserver.certserver/"]
RUN dotnet restore "src/opencertserver.certserver/opencertserver.certserver.csproj"
COPY . .
WORKDIR "/src/src/opencertserver.certserver"
RUN dotnet build "opencertserver.certserver.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "opencertserver.certserver.csproj" -c Release -o /app/publish

FROM base AS final
ENV ACCEPT_EULA=Y
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=true
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "opencertserver.certserver.dll"]
