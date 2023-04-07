using AuthServer.Sample.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using Moq;
using System.Collections;
using System.Security.Claims;

namespace AuthServer.Sample.Tests
{
    public class UnitTest1
    {
        [Fact]
        public void TestGenerateToken()
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

        class TestFeatureCollection : IFeatureCollection
        {
            public object? this[Type key] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

            public bool IsReadOnly => throw new NotImplementedException();

            public int Revision => throw new NotImplementedException();

            Dictionary<Type, object> data = new Dictionary<Type, object>();

            public TFeature? Get<TFeature>() => (TFeature)data.Where(x => x.Key == typeof(TFeature)).Select(x => x.Value).FirstOrDefault();

            public IEnumerator<KeyValuePair<Type, object>> GetEnumerator()
            {
                throw new NotImplementedException();
            }

            public void Set<TFeature>(TFeature? instance) => data[typeof(TFeature)] = instance;

            IEnumerator IEnumerable.GetEnumerator()
            {
                throw new NotImplementedException();
            }
        }

        [Fact]
        public void TestRequestContext()
        {
            HttpContextExtensions.RequestContext requestContext;

            var moqHttpContext = new Mock<HttpContext>();
            var moqHttpRequest = new Mock<HttpRequest>();
            var moqFeatures = new Mock<IFeatureCollection>();
            var features = new TestFeatureCollection();
            moqHttpRequest.Setup(x=>x.Path).Returns("/10000000-0000-0000-0000-000000000001/v2.0/.well-known/openid-configuration");
            moqHttpContext.Setup(x => x.Request).Returns(() => moqHttpRequest.Object);
            moqHttpContext.Setup(x => x.Features).Returns(() => features);

            var ipAddr = new byte[4] { 192, 168, 255, 251 };
            moqHttpContext.Setup(x => x.Connection.RemoteIpAddress).Returns(() => new System.Net.IPAddress(ipAddr));
            var callback = ()=> 
            moqFeatures.Setup(x=>x.Set<HttpContextExtensions.RequestContext>(It.IsAny<HttpContextExtensions.RequestContext?>()))
                .Callback<HttpContextExtensions.RequestContext>((ctx) => {
                    requestContext = ctx;
                });

            HttpContextExtensions.SetRequestContext(moqHttpContext.Object);
            var requestContext1 = HttpContextExtensions.GetRequestContext(moqHttpContext.Object);
        }
    }
}