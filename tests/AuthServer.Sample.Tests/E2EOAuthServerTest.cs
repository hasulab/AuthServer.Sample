using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using System.Net;

namespace AuthServer.Sample.Tests;

public class E2EOAuthServerTest
{
    [Fact]
    public async Task TestGenerateToken()
    {
        await using var application = new TestAuthWebApplication();

        var client = application.CreateClient();
        var response = await client.GetAsync("/swagger/index.html");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
public class TestAuthWebApplication : WebApplicationFactory<Program>
{
    protected override TestServer CreateServer(IWebHostBuilder builder)
    {
        return base.CreateServer(builder);
    }
}