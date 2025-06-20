using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Server.Extensions;

namespace OpenCertServer.Lambda;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container
    [RequiresDynamicCode(message:"Requires dynamic code generation for the Acme server.")]
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();
        services.AddAuthentication().AddCertificate()
            .Services
            .AddAcmeServer(Configuration)
            .AddAcmeInMemoryStore()
            .AddSingleton<ICsrValidator, DefaultCsrValidator>()
            .AddSingleton<ICertificateIssuer, DefaultIssuer>()
            .ConfigureOptions<ConfigureCertificateAuthenticationOptions>()
            .AddHealthChecks();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseHttpsRedirection();

        app.UseRouting();

        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
            endpoints.MapGet("/", async context =>
            {
                await context.Response.WriteAsync("Welcome to running ASP.NET Core on AWS Lambda");
            });
        });
    }
}
