using AuthServer.Sample.Extensions;
using AuthServer.Sample.Models;

namespace AuthServer.Sample.Tests;

public class StringExtensionsTest
{
    [Fact]
    public void TestBase64StringFormAndToConversion()
    {
        var plainText = "SampleText";
        var base64String = plainText.ToBase64String();
        var toPlainText = base64String.FromBase64String();
        Assert.Equal(toPlainText, plainText);
    }

    [Fact]
    public void FromAndToObjectTest()
    {
        var testData = new OAuthTokenRequest
        {
            client_id = "test",
            client_secret = "test",
        };

        var queryString = testData.ToDictionary().ToQueryString();
        Assert.NotNull(queryString);
        var base64String = queryString.ToBase64String();
        var toPlainText = base64String.FromBase64String();
        Assert.NotNull(toPlainText);
        var toDictionary = toPlainText.ToDictionary();
        var toTestData= toDictionary.ToObject<OAuthTokenRequest>();

        Assert.NotNull(toTestData);
    }
}