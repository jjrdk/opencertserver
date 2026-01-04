using System.Threading.Tasks;
using CertesSlim.Acme;
using CertesSlim.Extensions;
using NSubstitute;
using Xunit;

namespace CertesSlim.Tests;

public class IAccountContextExtensionsTests
{
    [Fact]
    public async Task CanDeactivateAccount()
    {
        var ctx = Substitute.For<IAccountContext>();

        var tsk = Task.FromResult(ctx);
        await tsk.Deactivate();
        await ctx.Received(1).Deactivate();
    }
}
