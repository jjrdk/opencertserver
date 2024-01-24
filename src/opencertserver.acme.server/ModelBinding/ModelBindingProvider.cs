namespace OpenCertServer.Acme.Server.ModelBinding;

using System.Diagnostics.CodeAnalysis;
using Abstractions.HttpModel.Requests;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;

public sealed class AcmeModelBindingProvider : IModelBinderProvider
{
    [UnconditionalSuppressMessage("AOT", "IL3050:Calling members annotated with 'RequiresDynamicCodeAttribute' may break functionality when AOT compiling.", Justification = "<Pending>")]
    public IModelBinder? GetBinder(ModelBinderProviderContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        var modelType = context.Metadata.ModelType;
        if (modelType == typeof(AcmeHeader))
        {
            return new BinderTypeModelBinder(typeof(AcmeHeaderBinder));
        }

        if (modelType.IsGenericType && modelType.GetGenericTypeDefinition() == typeof(AcmePayload<>)) {
            var type = typeof(AcmePayloadBinder<>).MakeGenericType(modelType.GetGenericArguments());
            return new BinderTypeModelBinder(type);
        }

        return null;
    }
}
