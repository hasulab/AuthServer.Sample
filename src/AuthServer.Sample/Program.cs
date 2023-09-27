using AuthServer.Sample.Extensions;
using AuthServer.Sample.Models;
using AuthServer.Sample.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddHttpContextAccessor()
    .AddSingleton<ResourceReader>()
    .AddScoped<WellKnownConfiguration>()
    .AddScoped<OAuth2Token>()
    .AddScoped<IJwtSigningService, JwtSigningService>()
    .AddScoped<IJwtUtils, JwtUtils>()
    .AddScoped<ClientDataProvider>()
    .AddScoped<ITenantsDataProvider, TenantsDataProvider>()
    .AddScoped<IAuthPageViewService, AuthPageViewService>()
//    .AddScoped<IAuthPageViewService, AuthPageViewService> ()
    .AddScoped<AuthRequestContext>((sp) =>
    {
        return sp.GetHttpContextFeature<AuthRequestContext>() ?? new AuthRequestContext();
    })
    .AddScoped<TenantSettings>((sp) =>
    {
        return sp.GetHttpContextFeature<TenantSettings>() ?? new TenantSettings();
    })
    ;
builder.Services.AddOptions<AuthSettings>().BindConfiguration("AuthSettings");

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new()
    {
        Title = builder.Environment.ApplicationName,
        Version = "v1"
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json",
                                    $"{builder.Environment.ApplicationName} v1"));
}


var currentFileProvider = app.Environment.ContentRootFileProvider as PhysicalFileProvider;

//get app current ContentRootFileProvider

var myFileProvider = new MyPhysicalFileProvider(currentFileProvider?.Root!, app?.Services?.GetService<IHttpContextAccessor>()!);
app.Environment.ContentRootFileProvider = myFileProvider;
var authSettings = app.Services.GetService<IOptions<AuthSettings>>();

app.UseStaticFiles(new StaticFileOptions()
{
    FileProvider = myFileProvider
});
var tmp = RoutePatternFactory.Parse("/{guid}/test/1");
//Microsoft.AspNetCore.Http.DefaultHttpContext

app.Use(async (context, next) =>
{
    context.SetRequestContext();

    if (context.Request.HasFormContentType)
    {
        await context.Request.FormContentToJson();
    }

    if (context.HasValidAuthPath())
    {
        context.SetTenantsContext();
    }

    await next(context);

    static async Task AwaitRequestTask()
    {
        await Task.CompletedTask;
    }
});
//app.UseEndpoints();
app.UseRouting();

app.MapGet("/", (LinkGenerator linker, IAuthPageViewService viewService) =>
       {
           var v2HomePage = linker.GetPathByName(AuthPage.HomePageV2, values: new { tenantId = Guid.Empty });
           return Results.Redirect(v2HomePage);
       })
    .WithName(AuthPage.HomePageV1);

app.MapGet("/{tenantId}/v2.0", (HttpRequest request, IAuthPageViewService viewService, string tenantId) =>
{
    return viewService.RenderHomePage(tenantId);
})
    .WithName(AuthPage.HomePageV2);

app.MapGet(WellKnownConfig.V1Url, (WellKnownConfiguration configuration, HttpRequest request, string tenantId) =>
{
    var siteName = $"{request.Scheme}://{request.Host.ToUriComponent()}";
    return Results.Text(configuration.GetV1(siteName, tenantId), "application/json"); 
})
    .WithName(WellKnownConfig.V1EPName);

app.MapGet(WellKnownConfig.V2Url, (WellKnownConfiguration configuration, HttpRequest request, string tenantId) =>
{
    var siteName = $"{request.Scheme}://{request.Host.ToUriComponent()}";
    return Results.Text(configuration.GetV2(siteName, tenantId), "application/json");
})
    .WithName(WellKnownConfig.V2EPName);

app.MapPost(Token.V1Url, (OAuth2Token tokenService,[FromBody] OAuthTokenRequest tokenRequest, [FromServices] AuthRequestContext requestContext) =>
{
    return AuthResults.HandleAuhResponse(tokenRequest.response_mode,
            ()=> tokenService.GenerateResponse(tokenRequest, requestContext));
})
    .WithName(Token.V1EPName);

app.MapPost(Token.V2Url, (OAuth2Token tokenService, [FromBody] OAuthTokenRequest tokenRequest, [FromServices] AuthRequestContext requestContext) =>
{
    return AuthResults.HandleAuhResponse(tokenRequest.response_mode,
            () => tokenService.GenerateResponse(tokenRequest, requestContext));
})
    .WithName(Token.V2EPName);


app.MapGet(Authorize.V1Url, (OAuth2Token tokenService, HttpRequest request, [FromServices] AuthRequestContext requestContext) =>
{
    var tokenRequest = request.QueryStringTo<OAuthTokenRequest>();
    return AuthResults.HandleAuhResponse(()=> tokenService.BuildAuthorizeResponse(tokenRequest, requestContext));
})
    .WithName(Authorize.V1GetEPName);

app.MapPost(Authorize.V1Url, (OAuth2Token tokenService, [FromBody] OAuthTokenRequest tokenRequest, [FromServices] AuthRequestContext requestContext) =>
{
    return AuthResults.HandleAuhResponse(tokenRequest.response_mode ?? ResponseMode.fragment,
            () => tokenService.GenerateResponse(tokenRequest, requestContext), tokenRequest.redirect_uri);

})
    .WithName(Authorize.V1PostEPName);

app.MapGet(Authorize.V2Url, (OAuth2Token tokenService, HttpRequest request, [FromServices] AuthRequestContext requestContext) =>
{
    var tokenRequest = request.QueryStringTo<OAuthTokenRequest>();
    return AuthResults.HandleAuhResponse(() => tokenService.BuildAuthorizeResponse(tokenRequest, requestContext));
})
    .WithName(Authorize.V2GetEPName);

app.MapPost(Authorize.V2Url, (OAuth2Token tokenService, [FromBody] OAuthTokenRequest tokenRequest, [FromServices] AuthRequestContext requestContext) =>
{
    return AuthResults.HandleAuhResponse(tokenRequest.response_mode ?? ResponseMode.fragment,
            () => tokenService.GenerateResponse(tokenRequest, requestContext));

})
    .WithName(Authorize.V2PostEPName);


app.MapGet(Login.V1Url, (HttpRequest request, IAuthPageViewService viewService, string tenantId) =>
{
    return viewService.RenderLogin(tenantId);
})
    .WithName(Login.V1GetEPName);

app.MapGet(Login.V2Url, (HttpRequest request, [FromServices] AuthRequestContext requestContext, string tenantId) =>
{
    return Results.Ok();
})
    .WithName(Login.V2GetEPName);

app.MapGet(Logout.V1Url, (HttpRequest request, [FromServices] AuthRequestContext requestContext, string tenantId) =>
{
    return Results.Ok();
})
    .WithName(Logout.V1GetEPName);

app.MapGet(Logout.V2Url, (HttpRequest request, [FromServices] AuthRequestContext requestContext, string tenantId) =>
{
    return Results.Ok();
})
    .WithName(Logout.V2GetEPName);

app.Use(async (context, next) =>
{
    //context.Request.HasFormContentType
    Console.WriteLine(context.Request.ContentType);
    Console.WriteLine($"2. Endpoint: {context.GetEndpoint()?.DisplayName ?? "(null)"}");
    await next(context);
});

app.Run();


public partial class Program { }
