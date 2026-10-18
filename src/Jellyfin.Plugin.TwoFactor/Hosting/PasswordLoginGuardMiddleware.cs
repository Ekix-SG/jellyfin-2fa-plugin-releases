using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactor.Hosting;

/// <summary>
/// Rejects Jellyfin's password-only login endpoints so that the only way to open a session with a
/// password is the two-factor page (which calls the server's managers directly, not these endpoints).
/// Blocked: <c>POST /Users/AuthenticateByName</c> and the obsolete <c>POST /Users/{id}/Authenticate</c>,
/// under any base URL or the /emby and /mediabrowser prefixes. Quick Connect, forgot-password and
/// existing tokens are not affected. The block is on regardless of whether the plugin is configured
/// correctly (fail closed); <see cref="PasswordLoginPolicy.AllowVariable"/> turns it off.
/// </summary>
public sealed partial class PasswordLoginGuardMiddleware
{
    private readonly RequestDelegate _next;
    private readonly PasswordLoginPolicy _policy;
    private readonly ILogger<PasswordLoginGuardMiddleware> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordLoginGuardMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware.</param>
    /// <param name="policy">The policy.</param>
    /// <param name="logger">The logger.</param>
    public PasswordLoginGuardMiddleware(RequestDelegate next, PasswordLoginPolicy policy, ILogger<PasswordLoginGuardMiddleware> logger)
    {
        _next = next;
        _policy = policy;
        _logger = logger;
        if (policy.Allowed)
        {
            _logger.LogWarning(
                "TwoFactor: {Variable} is set. Password-only logins through /Users/AuthenticateByName are ALLOWED, so the second factor can be bypassed. Use it only in an emergency.",
                PasswordLoginPolicy.AllowVariable);
        }
        else
        {
            _logger.LogInformation(
                "TwoFactor: password-only logins through /Users/AuthenticateByName are blocked. Use [BaseUrl]/TwoFactor/Login or Quick Connect.");
        }
    }

    /// <summary>
    /// Gets a value indicating whether a path is one of the blocked login endpoints.
    /// </summary>
    /// <param name="path">The request path.</param>
    /// <returns><c>true</c> if blocked.</returns>
    public static bool IsPasswordLoginPath(PathString path)
    {
        var value = path.Value;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        // ASP.NET routing ignores a trailing slash and the case of the path.
        var trimmed = value.TrimEnd('/');
        return trimmed.EndsWith("/users/authenticatebyname", StringComparison.OrdinalIgnoreCase)
            || LegacyAuthenticate().IsMatch(trimmed);
    }

    /// <summary>
    /// Handles a request.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <returns>A task.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        if (_policy.Allowed
            || HttpMethods.IsOptions(context.Request.Method)
            || !IsPasswordLoginPath(context.Request.Path))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        _logger.LogInformation(
            "TwoFactor: blocked a password-only login request (IP: {IP}).",
            context.Connection.RemoteIpAddress);
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new { error = "Password-only login is disabled. Use the two-factor login page." })
            .ConfigureAwait(false);
    }

    [GeneratedRegex("/users/[^/]+/authenticate$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LegacyAuthenticate();
}
