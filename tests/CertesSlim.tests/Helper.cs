using System;
using System.Linq.Expressions;
using System.Reflection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace CertesSlim.Tests;

public static partial class Helper
{
    public static void VerifyGetterSetter<TSource, TProperty>(
        this TSource source,
        Expression<Func<TSource, TProperty>> propertyLambda,
        TProperty value)
    {
        var member = propertyLambda.Body as MemberExpression;
        var propInfo = member.Member as PropertyInfo;

        propInfo.SetValue(source, value);
        var actualValue = propInfo.GetValue(source);

        Assert.Equal(value, (TProperty)actualValue);
    }

    public static string GetTestKey(this string algo)
    {
        return algo switch
        {
            SecurityAlgorithms.EcdsaSha256 => Keys.Es256Key,
            SecurityAlgorithms.EcdsaSha384 => Keys.Es384Key,
            SecurityAlgorithms.EcdsaSha512 => Keys.Es512Key,
            _ => Keys.Rs256Key
        };
    }
}