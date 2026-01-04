namespace OpenCertServer.Acme.Server.ModelBinding;

using System.Diagnostics.CodeAnalysis;
using Abstractions.HttpModel.Requests;
using Abstractions.RequestServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ModelBinding;
    
[RequiresUnreferencedCode("Uses unknown types")]
public sealed class AcmePayloadBinder<TPayload> : IModelBinder
{
    private readonly IAcmeRequestProvider _requestProvider;

    public AcmePayloadBinder(IAcmeRequestProvider requestProvider)
    {
        _requestProvider = requestProvider;
    }
        
    public Task BindModelAsync(ModelBindingContext bindingContext)
    {
        ArgumentNullException.ThrowIfNull(bindingContext);

        var acmePayload = new AcmePayload<TPayload>(_requestProvider.GetPayload<TPayload>() ?? throw new BadHttpRequestException("Invalid content"));
        bindingContext.Result = ModelBindingResult.Success(acmePayload);

        return Task.CompletedTask;
    }
}