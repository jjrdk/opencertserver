namespace OpenCertServer.Scep.Server;

using Handlers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registration of the SCEP server (RFC 8894).
/// </summary>
public static class ScepServerExtensions
{
    extension(IServiceCollection services)
    {
        /// <summary>
        /// Adds the SCEP server with the given options and challenge validator.
        /// </summary>
        public IServiceCollection AddScepServer(ScepServerOptions options, IScepChallengeValidator validator)
        {
            return services
                .AddSingleton(options)
                .AddSingleton(validator);
        }
    }

    extension(IEndpointRouteBuilder endpoints)
    {
        /// <summary>
        /// Maps the SCEP endpoint at <c>/scep</c> and <c>/scep/{profileName}</c>, GET and POST.
        /// SCEP clients authenticate through the challenge, not through HTTP, so the
        /// endpoint allows anonymous access.
        /// </summary>
        public IEndpointRouteBuilder MapScepServer(string path = "/scep")
        {
            var group = endpoints.MapGroup(path).AllowAnonymous();
            group.MapGet("/", ScepHandler.Get);
            group.MapPost("/", ScepHandler.Get);
            group.MapGet("/{profileName}", ScepHandler.GetProfile);
            group.MapPost("/{profileName}", ScepHandler.GetProfile);
            return endpoints;
        }
    }
}
