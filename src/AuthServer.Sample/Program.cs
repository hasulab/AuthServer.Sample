using System.Reflection;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.MapGet("/.well-known/openid-configuration", () =>
{
    var assembly = Assembly.GetExecutingAssembly();
    var resourceName = "AuthServer.Sample.Resources.openid-configuration.json";

    //var rr = assembly.GetManifestResourceNames();

    using (Stream stream = assembly.GetManifestResourceStream(resourceName))
    using (StreamReader reader = new StreamReader(stream))
    {
        return reader.ReadToEnd();
    }
});

app.MapGet("/v2.0/.well-known/openid-configuration", () =>
{
    var assembly = Assembly.GetExecutingAssembly();
    var resourceName = "AuthServer.Sample.Resources.V2.openid-configuration.json";

    //var rr = assembly.GetManifestResourceNames();

    using (Stream stream = assembly.GetManifestResourceStream(resourceName))
    using (StreamReader reader = new StreamReader(stream))
    {
        return reader.ReadToEnd();
    }
});


app.Run();
