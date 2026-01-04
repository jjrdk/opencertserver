using System;
using System.Linq.Expressions;
using System.Reflection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Certes;

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
        switch (algo)
        {
            case SecurityAlgorithms.EcdsaSha256:
                return Keys.Es256Key;
            case SecurityAlgorithms.EcdsaSha384:
                return Keys.Es384Key;
            case SecurityAlgorithms.EcdsaSha512:
                return Keys.Es512Key;
            default:
                return Keys.Rs256Key;
        }
    }
}