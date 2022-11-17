namespace OpenCertServer.Acme.Server.ModelBinding;

using Abstractions.RequestServices;
using Microsoft.AspNetCore.Mvc.ModelBinding;

public sealed class AcmeHeaderBinder : IModelBinder
{
    private readonly IAcmeRequestProvider _requestProvider;

    public AcmeHeaderBinder(IAcmeRequestProvider requestProvider)
    {
        _requestProvider = requestProvider;
    }

    public Task BindModelAsync(ModelBindingContext bindingContext)
    {
        if (bindingContext is null)
        {
            throw new ArgumentNullException(nameof(bindingContext));
        }

        var acmeHeader = _requestProvider.GetHeader();
        bindingContext.Result = ModelBindingResult.Success(acmeHeader);

        return Task.CompletedTask;
    }
}