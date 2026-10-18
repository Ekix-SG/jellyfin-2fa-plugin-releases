using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Totp;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactor.Hosting;

/// <summary>
/// Adds a script tag to jellyfin-web's <c>index.html</c> so that the web client's own login route is
/// replaced by the two-factor page. Nothing is injected, and nothing is written to disk, when the plugin
/// cannot work (no valid key or invalid TOTP variables): the original login must stay reachable then.
/// </summary>
public sealed partial class WebIndexMiddleware
{
    /// <summary>The tag that is injected. The path is relative to <c>[BaseUrl]/web/</c>.</summary>
    public const string ScriptTag = "<script src=\"../TwoFactor/redirect.js\"></script>";

    /// <summary>Text of the menu entry.</summary>
    public const string MenuLinkName = "Verificación en dos pasos";

    /// <summary>Target of the menu entry, relative to <c>[BaseUrl]/web/</c>.</summary>
    public const string MenuLinkUrl = "../TwoFactor/Manage";

    /// <summary>Text of the administrators' menu entry (shown to everyone; the page tells non-administrators it is not for them).</summary>
    public const string AdminMenuLinkName = "Administrar verificación en dos pasos";

    /// <summary>Target of the administrators' menu entry, relative to <c>[BaseUrl]/web/</c>.</summary>
    public const string AdminMenuLinkUrl = "../TwoFactor/Admin";

    private readonly RequestDelegate _next;
    private readonly bool _enabled;
    private readonly ILogger<WebIndexMiddleware> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="WebIndexMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware.</param>
    /// <param name="seeds">The seed store.</param>
    /// <param name="totp">The TOTP settings.</param>
    /// <param name="logger">The logger.</param>
    public WebIndexMiddleware(RequestDelegate next, ISeedStore seeds, TotpSettings totp, ILogger<WebIndexMiddleware> logger)
    {
        _next = next;
        _logger = logger;
        _enabled = seeds.IsAvailable && totp.IsValid;
        if (_enabled)
        {
            logger.LogInformation(
                "TwoFactor: the web client's login page is replaced by [BaseUrl]/TwoFactor/Login. Open /web/?nativelogin=1 to reach the original one.");
        }
        else
        {
            logger.LogWarning("TwoFactor: the web client's login page is NOT replaced because the plugin configuration is invalid.");
        }
    }

    /// <summary>
    /// Inserts the script tag right after <c>&lt;head&gt;</c>. The tag carries the web client's main bundle URL
    /// (<c>data-bundle</c>, as written in the page): the Android app only considers the page loaded once the
    /// WebView has requested that file, so the script requests it before redirecting.
    /// </summary>
    /// <param name="html">The page.</param>
    /// <returns>The page with the tag, or the same text if it has no head tag or already has the tag.</returns>
    public static string Inject(string html)
    {
        if (html.Contains("TwoFactor/redirect.js", StringComparison.Ordinal))
        {
            return html;
        }

        var index = html.IndexOf("<head>", StringComparison.OrdinalIgnoreCase);
        return index < 0 ? html : html.Insert(index + "<head>".Length, BuildScriptTag(FindMainBundle(html)));
    }

    /// <summary>
    /// Finds the main bundle URL (for example <c>main.jellyfin.bundle.js?abc123</c>) in the page.
    /// </summary>
    /// <param name="html">The page.</param>
    /// <returns>The URL exactly as written in the page, or <c>null</c>.</returns>
    public static string? FindMainBundle(string html)
    {
        var match = MainBundle().Match(html);
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>
    /// Builds the script tag.
    /// </summary>
    /// <param name="bundle">The main bundle URL as written in the page, or <c>null</c>.</param>
    /// <returns>The tag.</returns>
    public static string BuildScriptTag(string? bundle)
        => string.IsNullOrEmpty(bundle)
            ? ScriptTag
            : "<script src=\"../TwoFactor/redirect.js\" data-bundle=\"" + bundle + "\"></script>";

    /// <summary>
    /// Adds the "Verificación en dos pasos" entry to the <c>menuLinks</c> array of the web client's <c>config.json</c>,
    /// which jellyfin-web shows in its menu. The link is relative to <c>[BaseUrl]/web/</c>.
    /// </summary>
    /// <param name="json">The contents of <c>config.json</c>.</param>
    /// <returns>The edited JSON, or the same text if it cannot be parsed, is not an object, or already has the entry.</returns>
    public static string InjectMenuLink(string json)
    {
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(json);
        }
        catch (JsonException)
        {
            return json;
        }

        if (root is not JsonObject obj)
        {
            return json;
        }

        JsonArray links;
        if (obj["menuLinks"] is JsonArray existing)
        {
            links = existing;
        }
        else if (obj["menuLinks"] is null)
        {
            links = new JsonArray();
            obj["menuLinks"] = links;
        }
        else
        {
            return json;
        }

        var added = false;
        foreach (var (name, icon, url) in new[]
        {
            (MenuLinkName, "security", MenuLinkUrl),
            (AdminMenuLinkName, "admin_panel_settings", AdminMenuLinkUrl)
        })
        {
            if (links.Any(link => link is JsonObject o && o["url"]?.ToString() == url))
            {
                continue;
            }

            links.Add(new JsonObject { ["name"] = name, ["icon"] = icon, ["url"] = url });
            added = true;
        }

        if (!added)
        {
            return json;
        }

        return obj.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    /// <summary>
    /// Gets a value indicating whether the path is the web client's <c>config.json</c>.
    /// </summary>
    /// <param name="path">The request path (including any base URL).</param>
    /// <returns><c>true</c> for <c>.../web/config.json</c>.</returns>
    public static bool IsConfigPath(PathString path)
        => path.Value?.EndsWith("/web/config.json", StringComparison.OrdinalIgnoreCase) == true;

    [GeneratedRegex("""<script\b[^>]*?\bsrc=["']([^"'<>]*\bmain\.[^"'<>/]*\.bundle\.js[^"'<>]*)["']""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MainBundle();

    /// <summary>
    /// Gets a value indicating whether the path is the web client's entry page.
    /// </summary>
    /// <param name="path">The request path (including any base URL).</param>
    /// <returns><c>true</c> for <c>.../web/</c> and <c>.../web/index.html</c>.</returns>
    public static bool IsIndexPath(PathString path)
    {
        var value = path.Value;
        return value is not null
            && (value.EndsWith("/web/", StringComparison.OrdinalIgnoreCase)
                || value.EndsWith("/web/index.html", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Handles a request.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns>A task.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        var isIndex = IsIndexPath(context.Request.Path);
        var isConfig = !isIndex && IsConfigPath(context.Request.Path);
        if (!_enabled || !HttpMethods.IsGet(context.Request.Method) || !(isIndex || isConfig))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Ask the inner pipeline for the complete, uncompressed page so it can be edited.
        var headers = context.Request.Headers;
        headers.Remove("Accept-Encoding");
        headers.Remove("Range");
        headers.Remove("If-Range");
        headers.Remove("If-None-Match");
        headers.Remove("If-Modified-Since");

        var original = context.Response.Body;
        using var buffer = new MemoryStream();
        context.Response.Body = buffer;
        try
        {
            await _next(context).ConfigureAwait(false);
        }
        finally
        {
            context.Response.Body = original;
        }

        buffer.Position = 0;
        var expectedType = isIndex ? "text/html" : "application/json";
        var isExpected = context.Response.StatusCode == StatusCodes.Status200OK
            && context.Response.ContentType?.StartsWith(expectedType, StringComparison.OrdinalIgnoreCase) == true;
        if (!isExpected)
        {
            await buffer.CopyToAsync(original).ConfigureAwait(false);
            return;
        }

        var text = Encoding.UTF8.GetString(buffer.ToArray());
        var bytes = Encoding.UTF8.GetBytes(isIndex ? Inject(text) : InjectMenuLink(text));

        // The edited page no longer matches the validators the static file middleware computed.
        context.Response.Headers.Remove("ETag");
        context.Response.Headers.Remove("Last-Modified");
        context.Response.Headers.Remove("Accept-Ranges");
        if (isConfig)
        {
            // The menu entries must not stick in a client cache (the Android WebView keeps config.json otherwise).
            context.Response.Headers.CacheControl = "no-store";
            _logger.LogInformation(
                "TwoFactor: served config.json with the menu entries (IP: {IP}, client: {UserAgent}).",
                context.Connection.RemoteIpAddress,
                context.Request.Headers.UserAgent.ToString());
        }

        context.Response.ContentLength = bytes.Length;
        await original.WriteAsync(bytes).ConfigureAwait(false);
    }
}
