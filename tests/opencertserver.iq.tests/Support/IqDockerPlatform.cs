namespace OpenCertServer.Iq.Tests.Support;

internal sealed record IqDockerPlatform(string Architecture, string Platform)
{
    public static IqDockerPlatform Resolve(string operatingSystem, string architecture, string? requestedArchitecture)
    {
        if (!string.Equals(operatingSystem, "linux", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"IQ clients require a Linux Docker daemon, got '{operatingSystem}'. On Windows, switch Docker Desktop to Linux containers.");
        }

        if (!string.IsNullOrEmpty(requestedArchitecture))
        {
            return requestedArchitecture switch
            {
                "x64" => new("x64", "linux/amd64"),
                "arm64" => new("arm64", "linux/arm64"),
                _ => throw new InvalidOperationException(
                    $"IQ_DOCKER_ARCH must be 'x64' or 'arm64', got '{requestedArchitecture}'.")
            };
        }

        return architecture switch
        {
            "amd64" or "x86_64" or "x64" => new("x64", "linux/amd64"),
            "arm64" or "aarch64" => new("arm64", "linux/arm64"),
            _ => throw new InvalidOperationException($"Unsupported IQ Docker architecture '{architecture}'.")
        };
    }
}
