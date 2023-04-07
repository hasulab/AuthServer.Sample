using AuthServer.Sample.Services;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace AuthServer.Sample.Tests
{
    public class OAuth2TokenTest
    {
        [Fact]
        public void TestGenerateToken()
        {
            var util = new JwtUtils(new TestOptions(new AppSettings() { SecretKey = "SecretKeySecretKeySecretKeySecretKeySecretKeySecretKeySecretKeyS" }));
            var token = util.GenerateToken(new ClaimsIdentity(new List<Claim> { new Claim("Id", "TestId") }));
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

        [Fact]
        public void TestGenerateTokenFromRequest()
        {
            var util = new JwtUtils(new TestOptions(new AppSettings() { SecretKey = "SecretKeySecretKeySecretKeySecretKeySecretKeySecretKeySecretKeyS" }));
            var claimsProvider = new ClaimsProvider();
            var service = new OAuth2Token(util, claimsProvider);
            var tokenRequest = new OAuthTokenRequest();
            
            service.GetResponse(tokenRequest, reqContext);
        }
    }
}