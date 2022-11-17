namespace OpenCertServer.Acme.Server.Filters;

using Abstractions.Model.Exceptions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;

public sealed class AcmeExceptionFilter : IExceptionFilter
{
    private readonly ILogger<AcmeExceptionFilter> _logger;

    public AcmeExceptionFilter(ILogger<AcmeExceptionFilter> logger)
    {
        _logger = logger;
    }

    public void OnException(ExceptionContext context)
    {
        if (context.Exception is AcmeException acmeException)
        {
            _logger.LogDebug("Detected {exceptionType}. Converting to BadRequest.", acmeException.GetType());
#if DEBUG
            _logger.LogError(context.Exception, "AcmeException detected.");
#endif

            ObjectResult result = acmeException switch
            {
                ConflictRequestException => new ConflictObjectResult(acmeException.GetHttpError()),
                NotAllowedException => new UnauthorizedObjectResult(acmeException.GetHttpError()),
                NotFoundException => new NotFoundObjectResult(acmeException.GetHttpError()),
                _ => new BadRequestObjectResult(acmeException.GetHttpError())
            };

            result.ContentTypes.Add("application/problem+json");
            context.Result = result;
        }
    }
}