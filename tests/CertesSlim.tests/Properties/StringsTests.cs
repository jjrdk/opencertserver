using System.Globalization;
using CertesSlim.Properties;
using Xunit;

namespace CertesSlim.Tests.Properties;

public class StringsTests
{
    [Fact]
    public void CanCreateInstance()
    {
        _ = new Strings();
    }

    [Fact]
    public void CanGetSetCulture()
    {
        Strings.Culture = CultureInfo.GetCultureInfo("fr-CA");
        Assert.Equal(CultureInfo.GetCultureInfo("fr-CA"), Strings.Culture);
    }
}
