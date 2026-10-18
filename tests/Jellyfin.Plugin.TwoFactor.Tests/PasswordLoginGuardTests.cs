using Jellyfin.Plugin.TwoFactor.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public class PasswordLoginGuardTests
{
    private static Func<string, string?> Env(string? value)
        => name => name == PasswordLoginPolicy.AllowVariable ? value : null;

    private static async Task<(DefaultHttpContext Context, bool Reached)> Send(string path, string method, bool allowed = false)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        var reached = false;
        var middleware = new PasswordLoginGuardMiddleware(
            _ =>
            {
                reached = true;
                return Task.CompletedTask;
            },
            new PasswordLoginPolicy(allowed),
            NullLogger<PasswordLoginGuardMiddleware>.Instance);
        await middleware.InvokeAsync(context);
        return (context, reached);
    }

    [Theory]
    [InlineData("/Users/AuthenticateByName")]
    [InlineData("/users/authenticatebyname")]
    [InlineData("/USERS/AUTHENTICATEBYNAME")]
    [InlineData("/Users/AuthenticateByName/")]
    [InlineData("/Users/AuthenticateByName//")]
    [InlineData("/jellyfin/Users/AuthenticateByName")]
    [InlineData("/emby/Users/AuthenticateByName")]
    [InlineData("/mediabrowser/Users/AuthenticateByName")]
    [InlineData("/Users/0a1b2c3d4e5f60718293a4b5c6d7e8f9/Authenticate")]
    [InlineData("/Users/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9/authenticate/")]
    [InlineData("/emby/Users/abc/Authenticate")]
    public void PasswordLoginPaths_AreRecognized(string path)
    {
        Assert.True(PasswordLoginGuardMiddleware.IsPasswordLoginPath(new PathString(path)));
    }

    [Theory]
    [InlineData("/Users/AuthenticateWithQuickConnect")]
    [InlineData("/QuickConnect/Initiate")]
    [InlineData("/QuickConnect/Connect")]
    [InlineData("/QuickConnect/Authorize")]
    [InlineData("/Users/ForgotPassword")]
    [InlineData("/Users/ForgotPassword/Pin")]
    [InlineData("/Users/Public")]
    [InlineData("/Users/Me")]
    [InlineData("/Users/abc/Password")]
    [InlineData("/Users/abc")]
    [InlineData("/Users")]
    [InlineData("/TwoFactor/Step1")]
    [InlineData("/TwoFactor/Login")]
    [InlineData("/web/")]
    [InlineData("/")]
    [InlineData("")]
    public void OtherPaths_AreNotBlocked(string path)
    {
        Assert.False(PasswordLoginGuardMiddleware.IsPasswordLoginPath(new PathString(path)));
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("GET")]
    [InlineData("PUT")]
    public async Task BlockedPath_ReturnsUnauthorized_AndNeverReachesJellyfin(string method)
    {
        var (context, reached) = await Send("/Users/AuthenticateByName", method);
        Assert.False(reached);
        Assert.Equal(401, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        var body = new StreamReader(context.Response.Body).ReadToEnd();
        Assert.Contains("two-factor", body);
        Assert.DoesNotContain("TWOFACTOR_", body);
    }

    [Fact]
    public async Task LegacyRoute_IsBlockedToo()
    {
        var (context, reached) = await Send("/Users/abc/Authenticate", "POST");
        Assert.False(reached);
        Assert.Equal(401, context.Response.StatusCode);
    }

    [Fact]
    public async Task CorsPreflight_PassesThrough()
    {
        var (context, reached) = await Send("/Users/AuthenticateByName", "OPTIONS");
        Assert.True(reached);
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Theory]
    [InlineData("/Users/AuthenticateWithQuickConnect")]
    [InlineData("/Users/ForgotPassword/Pin")]
    [InlineData("/TwoFactor/Step1")]
    public async Task OtherEndpoints_ReachJellyfin(string path)
    {
        var (_, reached) = await Send(path, "POST");
        Assert.True(reached);
    }

    [Fact]
    public async Task EmergencyPolicy_LetsPasswordLoginThrough()
    {
        var (context, reached) = await Send("/Users/AuthenticateByName", "POST", allowed: true);
        Assert.True(reached);
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("  ", false)]
    [InlineData("false", false)]
    [InlineData("FALSE", false)]
    [InlineData("0", false)]
    [InlineData("true", true)]
    [InlineData("True", true)]
    [InlineData(" true ", true)]
    [InlineData("1", true)]
    public void Policy_ParsesTheVariable(string? value, bool expected)
    {
        var policy = PasswordLoginPolicy.FromEnvironment(Env(value), out var error);
        Assert.Equal(expected, policy.Allowed);
        Assert.Null(error);
    }

    [Theory]
    [InlineData("yes")]
    [InlineData("on")]
    [InlineData("2")]
    [InlineData("truee")]
    public void Policy_InvalidValue_IsAnErrorAndStaysBlocked(string value)
    {
        var policy = PasswordLoginPolicy.FromEnvironment(Env(value), out var error);
        Assert.False(policy.Allowed);
        Assert.NotNull(error);
        Assert.Contains(PasswordLoginPolicy.AllowVariable, error);
        Assert.DoesNotContain("(" + value + ")", error);
    }
}
