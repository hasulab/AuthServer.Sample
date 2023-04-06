using AuthServer.Sample.Services;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace AuthServer.Sample.Tests
{
    public class UnitTest1
    {
        [Fact]
        public void Test1()
        {
            var util = new JwtUtils(new TestOptions(new AppSettings() { SecretKey = "SecretKeySecretKeySecretKeySecretKeySecretKeySecretKeySecretKeyS" }));
            var token = util.GenerateToken(new ClaimsIdentity( new List<Claim> { new Claim("Id","TestId") } ));
        }

        class TestOptions : IOptions<AppSettings>
        {
            private readonly AppSettings appSettings;

            public TestOptions(AppSettings appSettings)
            {
                this.appSettings = appSettings;
            }
            public AppSettings Value => appSettings;
        }
    }
}