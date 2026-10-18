using System.Text;
using Jellyfin.Plugin.TwoFactor.Hosting;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Totp;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public class WebIndexMiddlewareTests
{
    private const string Html = "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Jellyfin</title>\n</head>\n<body></body>\n</html>";

    private sealed class FakeSeeds(bool available) : ISeedStore
    {
        public bool IsAvailable { get; } = available;

        public bool IsEnabled(Guid userId) => throw new NotSupportedException();

        public bool TryEnroll(Guid userId, byte[] secret, long acceptedCounter, TotpOptions options) => throw new NotSupportedException();

        public bool TryAcceptCode(Guid userId, string? code, DateTimeOffset now) => throw new NotSupportedException();

        public bool TryReplace(Guid userId, byte[] secret, long acceptedCounter, TotpOptions options) => throw new NotSupportedException();

        public bool Remove(Guid userId) => throw new NotSupportedException();
    }

    private static WebIndexMiddleware Create(RequestDelegate next, bool available = true, bool validSettings = true)
        => new(next, new FakeSeeds(available), new TotpSettings(TotpOptions.Default, validSettings), NullLogger<WebIndexMiddleware>.Instance);

    private static DefaultHttpContext NewContext(string path, string method = "GET")
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static string ReadBody(HttpContext context)
    {
        context.Response.Body.Position = 0;
        return new StreamReader(context.Response.Body, Encoding.UTF8).ReadToEnd();
    }

    private static RequestDelegate Serve(string body, string contentType = "text/html", int status = 200)
        => async context =>
        {
            context.Response.StatusCode = status;
            context.Response.ContentType = contentType;
            context.Response.ContentLength = Encoding.UTF8.GetByteCount(body);
            context.Response.Headers.ETag = "\"abc\"";
            context.Response.Headers.LastModified = "Sat, 17 Oct 2026 10:00:00 GMT";
            await context.Response.WriteAsync(body);
        };

    [Fact]
    public void Inject_PutsTheScriptRightAfterHead()
    {
        var result = WebIndexMiddleware.Inject(Html);
        Assert.Contains("<head><script src=\"../TwoFactor/redirect.js\"></script>\n<meta", result);
        Assert.Equal(1, result.Split("redirect.js").Length - 1);
    }

    [Fact]
    public void Inject_CarriesTheMainBundleUrl_ForTheAndroidApp()
    {
        const string page = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><script defer=\"defer\" src=\"main.jellyfin.bundle.js?abc123\"></script></head><body></body></html>";
        var result = WebIndexMiddleware.Inject(page);
        Assert.Contains("<head><script src=\"../TwoFactor/redirect.js\" data-bundle=\"main.jellyfin.bundle.js?abc123\"></script><meta", result);
        Assert.Equal(1, result.Split("redirect.js").Length - 1);
    }

    [Theory]
    [InlineData("<script defer=\"defer\" src=\"main.jellyfin.bundle.js?abc\"></script>", "main.jellyfin.bundle.js?abc")]
    [InlineData("<script src=\"main.jellyfin.bundle.js\"></script>", "main.jellyfin.bundle.js")]
    [InlineData("<script src='/web/main.jellyfin.bundle.js?x=1'></script>", "/web/main.jellyfin.bundle.js?x=1")]
    [InlineData("<SCRIPT SRC=\"Main.Jellyfin.Bundle.JS\"></SCRIPT>", "Main.Jellyfin.Bundle.JS")]
    [InlineData("<script defer src=\"runtime.js\"></script><script defer src=\"main.jellyfin.bundle.js?z\"></script>", "main.jellyfin.bundle.js?z")]
    public void FindMainBundle_FindsTheBundleTheAppWaitsFor(string html, string expected)
    {
        Assert.Equal(expected, WebIndexMiddleware.FindMainBundle(html));
    }

    [Theory]
    [InlineData("<script src=\"serviceworker.js\"></script>")]
    [InlineData("<script src=\"vendors.bundle.js\"></script>")]
    [InlineData("<script src=\"main.abc123.chunk.js\"></script>")]
    [InlineData("<link rel=\"preload\" href=\"main.jellyfin.bundle.js\">")]
    [InlineData("<!-- main.jellyfin.bundle.js -->")]
    [InlineData("")]
    public void FindMainBundle_IgnoresEverythingElse(string html)
    {
        Assert.Null(WebIndexMiddleware.FindMainBundle(html));
    }

    [Fact]
    public void BuildScriptTag_WithoutBundle_IsThePlainTag()
    {
        Assert.Equal(WebIndexMiddleware.ScriptTag, WebIndexMiddleware.BuildScriptTag(null));
        Assert.Equal(WebIndexMiddleware.ScriptTag, WebIndexMiddleware.BuildScriptTag(string.Empty));
    }

    [Fact]
    public void Inject_IsIdempotent_AndIgnoresPagesWithoutHead()
    {
        var once = WebIndexMiddleware.Inject(Html);
        Assert.Equal(once, WebIndexMiddleware.Inject(once));
        Assert.Equal("<p>no head</p>", WebIndexMiddleware.Inject("<p>no head</p>"));
        Assert.Contains("redirect.js", WebIndexMiddleware.Inject("<HEAD></HEAD>"));
    }

    [Theory]
    [InlineData("/web/", true)]
    [InlineData("/web/index.html", true)]
    [InlineData("/WEB/INDEX.HTML", true)]
    [InlineData("/jellyfin/web/", true)]
    [InlineData("/jellyfin/web/index.html", true)]
    [InlineData("/web", false)]
    [InlineData("/web/main.bundle.js", false)]
    [InlineData("/TwoFactor/Login", false)]
    [InlineData("/Users/AuthenticateByName", false)]
    [InlineData("/", false)]
    public void IsIndexPath_OnlyMatchesTheEntryPage(string path, bool expected)
    {
        Assert.Equal(expected, WebIndexMiddleware.IsIndexPath(new PathString(path)));
    }

    [Theory]
    [InlineData("/web/")]
    [InlineData("/web/index.html")]
    [InlineData("/base/web/")]
    public async Task IndexPage_GetsTheScript_WithConsistentHeaders(string path)
    {
        var context = NewContext(path);
        await Create(Serve(Html)).InvokeAsync(context);

        var body = ReadBody(context);
        Assert.Contains("redirect.js", body);
        Assert.Equal(Encoding.UTF8.GetByteCount(body), context.Response.ContentLength);
        Assert.False(context.Response.Headers.ContainsKey("ETag"));
        Assert.False(context.Response.Headers.ContainsKey("Last-Modified"));
        Assert.Equal(200, context.Response.StatusCode);
        Assert.StartsWith("text/html", context.Response.ContentType);
    }

    [Fact]
    public async Task InnerPipeline_IsAskedForAFullUncompressedPage()
    {
        var context = NewContext("/web/");
        context.Request.Headers.AcceptEncoding = "gzip, br";
        context.Request.Headers.Range = "bytes=0-10";
        context.Request.Headers.IfNoneMatch = "\"abc\"";
        context.Request.Headers.IfModifiedSince = "Sat, 17 Oct 2026 10:00:00 GMT";

        IHeaderDictionary? seen = null;
        await Create(async c =>
        {
            seen = new HeaderDictionary(c.Request.Headers.ToDictionary(h => h.Key, h => h.Value));
            await Serve(Html)(c);
        }).InvokeAsync(context);

        Assert.NotNull(seen);
        Assert.False(seen!.ContainsKey("Accept-Encoding"));
        Assert.False(seen.ContainsKey("Range"));
        Assert.False(seen.ContainsKey("If-None-Match"));
        Assert.False(seen.ContainsKey("If-Modified-Since"));
    }

    [Theory]
    [InlineData("/web/main.bundle.js")]
    [InlineData("/Users/AuthenticateByName")]
    [InlineData("/TwoFactor/Login")]
    [InlineData("/")]
    public async Task OtherPaths_PassThroughUntouched(string path)
    {
        var context = NewContext(path);
        await Create(Serve(Html)).InvokeAsync(context);
        Assert.Equal(Html, ReadBody(context));
        Assert.True(context.Response.Headers.ContainsKey("ETag"));
    }

    [Fact]
    public async Task NonGetRequests_PassThroughUntouched()
    {
        var context = NewContext("/web/", "POST");
        await Create(Serve(Html)).InvokeAsync(context);
        Assert.Equal(Html, ReadBody(context));
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(false, false)]
    public async Task InvalidConfiguration_NeverInjects_SoTheOriginalLoginStaysReachable(bool available, bool validSettings)
    {
        var context = NewContext("/web/");
        await Create(Serve(Html), available, validSettings).InvokeAsync(context);
        Assert.Equal(Html, ReadBody(context));
    }

    [Fact]
    public async Task NonHtmlOrErrorResponses_AreCopiedAsTheyAre()
    {
        var notFound = NewContext("/web/index.html");
        await Create(Serve("missing", "text/plain", 404)).InvokeAsync(notFound);
        Assert.Equal(404, notFound.Response.StatusCode);
        Assert.Equal("missing", ReadBody(notFound));

        var json = NewContext("/web/index.html");
        await Create(Serve("{\"a\":1}", "application/json")).InvokeAsync(json);
        Assert.Equal("{\"a\":1}", ReadBody(json));
    }

    [Fact]
    public async Task Utf8Content_SurvivesTheRoundTrip()
    {
        var html = Html.Replace("Jellyfin", "Jellyfin ñ ó 日本", StringComparison.Ordinal);
        var context = NewContext("/web/");
        await Create(Serve(html)).InvokeAsync(context);
        Assert.Contains("Jellyfin ñ ó 日本", ReadBody(context));
    }
}
