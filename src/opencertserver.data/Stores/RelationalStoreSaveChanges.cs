namespace OpenCertServer.Data.Stores;

using Microsoft.EntityFrameworkCore;
using OpenCertServer.Acme.Abstractions.Exceptions;

internal static class RelationalStoreSaveChanges
{
    internal static async Task SaveAggregateAsync(this CaDbContext context,
        IRelationalStoreProvider provider, CancellationToken cancellationToken)
    {
        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            throw new ConcurrencyException();
        }
        catch (DbUpdateException exception) when (provider.IsUniqueViolation(exception))
        {
            throw new ConcurrencyException();
        }
    }
}
