namespace OpenCertServer.Acme.Abstractions.Storage
{
    using System.Threading;
    using System.Threading.Tasks;
    using Model;

    public interface IStoreAccounts
    {
        Task SaveAccount(Account account, CancellationToken cancellationToken);
        Task<Account?> LoadAccount(string accountId, CancellationToken cancellationToken);
    }
}
