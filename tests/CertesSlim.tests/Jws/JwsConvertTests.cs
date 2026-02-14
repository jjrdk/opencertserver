using System.Text;
using CertesSlim.Json;
using Xunit;

namespace CertesSlim.Tests.Jws;

public class JwsConvertTests
{
    [Fact]
    public void CanConvertToBase64String()
    {
        foreach (var s in new[]
            {
                "a", "ab", "abc", "abcd"
            })
        {
            var data = Encoding.UTF8.GetBytes(s);
            var str = data.ToBase64String();
            var reverted = str.FromBase64String();
            Assert.Equal(data, reverted);
        }

        Assert.Throws<AcmeException>(() => "/not a valid base 64 string/!".FromBase64String());
    }
}
