using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.TestUtilities;
using Xunit;

namespace OpenCertServer.Lambda.Tests;

public class ValuesControllerTests
{
    [Fact]
    [RequiresUnreferencedCode(message: "Requires unreferenced code for the Lambda function handler.")]
    [RequiresDynamicCode(message: "Requires dynamic code generation for the Lambda function handler.")]
    public async Task TestGet()
    {
        var lambdaFunction = new LambdaEntryPoint();

        var requestStr = await File.ReadAllTextAsync("./SampleRequests/ValuesController-Get.json");
        var request = JsonSerializer.Deserialize<APIGatewayProxyRequest>(requestStr, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });
        var context = new TestLambdaContext();
        var response = await lambdaFunction.FunctionHandlerAsync(request, context);

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("[\"value1\",\"value2\"]", response.Body);
        Assert.True(response.MultiValueHeaders.ContainsKey("Content-Type"));
        Assert.Equal("application/json; charset=utf-8", response.MultiValueHeaders["Content-Type"][0]);
    }
}
