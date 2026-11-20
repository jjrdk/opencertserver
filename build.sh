#!/usr/bin/env bash

dotnet run --framework net10.0 --project ./build/opencertserver.build/opencertserver.build.csproj -- "$@"
