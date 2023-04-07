using AuthServer.Sample.Extentions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Moq;
using System.Collections;

namespace AuthServer.Sample.Tests
{
    public class RequestContextTests
    {
        

        [Fact]
        public void TestRequestContext()
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
        }
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
}