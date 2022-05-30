namespace OpenCertServer.Acme.Abstractions.Storage
{
    using System.Threading;
    using System.Threading.Tasks;
    using Model;

    public interface IAccountStore
    {
        Task SaveAccountAsync(Account account, CancellationToken cancellationToken);
        Task<Account?> LoadAccountAsync(string accountId, CancellationToken cancellationToken);
    }
}
