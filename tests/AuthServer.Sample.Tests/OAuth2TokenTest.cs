using AuthServer.Sample.Services;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Moq;
using System.Security.Claims;
using AuthServer.Sample.Extentions;
using Microsoft.VisualStudio.TestPlatform.CrossPlatEngine.Adapter;

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
            HttpContextExtensions.RequestContext requestContext;

            var moqHttpContext = new Mock<HttpContext>();
            var moqHttpRequest = new Mock<HttpRequest>();
            var moqFeatures = new Mock<IFeatureCollection>();
            var features = new TestFeatureCollection();

            moqHttpContext.Setup(x => x.Request).Returns(() => moqHttpRequest.Object);
            moqHttpContext.Setup(x => x.Features).Returns(() => features);

            moqHttpRequest.Setup(x => x.Path).Returns("/10000000-0000-0000-0000-000000000001/v2.0/.well-known/openid-configuration");
            moqHttpRequest.Setup(x => x.Scheme).Returns("https");
            moqHttpRequest.Setup(x => x.Host).Returns(new HostString("testserver"));

            var ipAddr = new byte[4] { 192, 168, 255, 251 };
            moqHttpContext.Setup(x => x.Connection.RemoteIpAddress).Returns(() => new System.Net.IPAddress(ipAddr));

            HttpContextExtensions.SetRequestContext(moqHttpContext.Object);
            var requestContext1 = HttpContextExtensions.GetRequestContext(moqHttpContext.Object);

            var util = new JwtUtils(new TestOptions(new AppSettings() { SecretKey = "SecretKeySecretKeySecretKeySecretKeySecretKeySecretKeySecretKeyS" }));
            var claimsProvider = new ClaimsProvider();
            var service = new OAuth2Token(util, claimsProvider);
            var tokenRequest = new OAuthTokenRequest();
            var jwtToken = service.GetResponse(tokenRequest, requestContext1);

        }
    }
}