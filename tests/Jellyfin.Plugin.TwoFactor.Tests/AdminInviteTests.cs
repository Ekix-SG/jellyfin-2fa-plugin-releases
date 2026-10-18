using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactor.Api;
using Jellyfin.Plugin.TwoFactor.Hosting;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Tickets;
using Jellyfin.Plugin.TwoFactor.Totp;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Jellyfin.Plugin.TwoFactor.Tests;

/// <summary>The administrators' endpoints, through the real ASP.NET pipeline with a stand-in for Jellyfin's authentication.</summary>
public sealed class AdminInviteTests : IDisposable
{
    private const string AdminHeader = "X-Test-Role";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tf-admin-" + Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _time = new(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
    private readonly SeedCipher _cipher = new(RandomNumberGenerator.GetBytes(32));
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly User _ana = new("ana", "provider", "reset") { Id = Guid.NewGuid() };
    private readonly FileSeedStore _seeds;
    private readonly FileInviteStore _invites;
    private readonly IHost _host;
    private readonly HttpClient _client;

    public AdminInviteTests()
    {
        _seeds = new FileSeedStore(_dir, _cipher, NullLogger.Instance);
        _invites = new FileInviteStore(_dir, _cipher, _time, NullLogger.Instance);
        _users.GetUsers().Returns(new[] { _ana });
        _users.GetUserById(_ana.Id).Returns(_ana);
        _users.GetUserByName("ana").Returns(_ana);

        _host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddSingleton(_users);
                    services.AddSingleton(Substitute.For<ISessionManager>());
                    services.AddSingleton<ISeedStore>(_seeds);
                    services.AddSingleton<IInviteStore>(_invites);
                    services.AddSingleton(new TotpSettings(TotpOptions.Default, true));
                    services.AddSingleton<TimeProvider>(_time);
                    services.AddSingleton<TicketStore>();
                    services.AddSingleton<LoginThrottle>();
                    services.AddLogging();
                    services.AddAuthentication("test").AddScheme<AuthenticationSchemeOptions, StandInAuthHandler>("test", null);

                    // Stand-in for Jellyfin's "RequiresElevation" policy: an authenticated administrator.
                    services.AddAuthorization(options => options.AddPolicy("RequiresElevation", p => p.RequireClaim("admin", "true")));
                    services.AddControllers().AddApplicationPart(typeof(TwoFactorAdminController).Assembly);
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints => endpoints.MapControllers());
                }))
            .Start();
        _client = _host.GetTestClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _host.Dispose();
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    private HttpRequestMessage Request(HttpMethod method, string url, string? role, object? body = null)
    {
        var request = new HttpRequestMessage(method, url);
        if (role is not null)
        {
            request.Headers.Add(AdminHeader, role);
        }

        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        return request;
    }

    [Theory]
    [InlineData("GET", "/TwoFactor/Admin/Users")]
    [InlineData("POST", "/TwoFactor/Admin/Invite")]
    [InlineData("POST", "/TwoFactor/Admin/Invite/Revoke")]
    [InlineData("POST", "/TwoFactor/Admin/Reset")]
    public async Task AdminEndpoints_AreRefusedWithoutASession(string method, string url)
    {
        var response = await _client.SendAsync(Request(new HttpMethod(method), url, null, new { userId = _ana.Id }));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(_invites.GetActive(_ana.Id));
    }

    [Theory]
    [InlineData("GET", "/TwoFactor/Admin/Users")]
    [InlineData("POST", "/TwoFactor/Admin/Invite")]
    [InlineData("POST", "/TwoFactor/Admin/Invite/Revoke")]
    [InlineData("POST", "/TwoFactor/Admin/Reset")]
    public async Task AdminEndpoints_AreRefusedForANormalUser(string method, string url)
    {
        var response = await _client.SendAsync(Request(new HttpMethod(method), url, "user", new { userId = _ana.Id }));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(_invites.GetActive(_ana.Id));
    }

    [Fact]
    public void EveryAdminAction_HasTheElevationPolicy_AndNoneIsAnonymous()
    {
        var controllers = new[] { typeof(TwoFactorAdminController) };
        foreach (var type in controllers)
        {
            var attribute = Assert.Single(type.GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AuthorizeAttribute), true).Cast<Microsoft.AspNetCore.Authorization.AuthorizeAttribute>());
            Assert.Equal("RequiresElevation", attribute.Policy);
            Assert.All(
                type.GetMethods().Where(m => m.DeclaringType == type && m.GetCustomAttributes(typeof(Microsoft.AspNetCore.Mvc.Routing.HttpMethodAttribute), true).Length > 0),
                m => Assert.Empty(m.GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute), true)));
        }
    }

    [Fact]
    public async Task List_ShowsEnrollmentState_AndTheCodeExpiry()
    {
        var invite = _invites.Create(_ana.Id, TimeSpan.FromHours(24));

        var response = await _client.SendAsync(Request(HttpMethod.Get, "/TwoFactor/Admin/Users", "admin"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var rows = await response.Content.ReadFromJsonAsync<List<AdminUserRow>>();
        var row = Assert.Single(rows!);
        Assert.Equal("ana", row.Name);
        Assert.False(row.Enrolled);
        Assert.Equal(invite.ExpiresAt, row.InviteExpiresAt);
        Assert.DoesNotContain(invite.Code, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Generate_ReturnsThePlainCodeOnce_AndANewOneInvalidatesTheOld()
    {
        var first = await (await _client.SendAsync(Request(HttpMethod.Post, "/TwoFactor/Admin/Invite", "admin", new { userId = _ana.Id })))
            .Content.ReadFromJsonAsync<AdminInviteResponse>();
        var second = await (await _client.SendAsync(Request(HttpMethod.Post, "/TwoFactor/Admin/Invite", "admin", new { username = "ana" })))
            .Content.ReadFromJsonAsync<AdminInviteResponse>();

        Assert.Equal(10, first!.Code.Length);
        Assert.NotEqual(first.Code, second!.Code);
        Assert.Null(_invites.TryValidate(_ana.Id, first.Code));
        Assert.NotNull(_invites.TryValidate(_ana.Id, second.Code));
    }

    [Fact]
    public async Task Generate_ForAnEnrolledUser_IsRefused()
    {
        _seeds.TryEnroll(_ana.Id, TotpService.GenerateSecret(), 1, TotpOptions.Default);

        var response = await _client.SendAsync(Request(HttpMethod.Post, "/TwoFactor/Admin/Invite", "admin", new { userId = _ana.Id }));

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Null(_invites.GetActive(_ana.Id));
    }

    [Fact]
    public async Task Revoke_DeletesTheLiveCode()
    {
        var invite = _invites.Create(_ana.Id, TimeSpan.FromHours(24));

        var response = await _client.SendAsync(Request(HttpMethod.Post, "/TwoFactor/Admin/Invite/Revoke", "admin", new { userId = _ana.Id }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(_invites.TryValidate(_ana.Id, invite.Code));
    }

    [Fact]
    public async Task Generate_ForAnUnknownUser_IsNotFound()
    {
        var response = await _client.SendAsync(Request(HttpMethod.Post, "/TwoFactor/Admin/Invite", "admin", new { userId = Guid.NewGuid() }));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task TheCodeIsNeverWrittenToTheLog()
    {
        var logger = new CapturingLogger<TwoFactorAdminController>();
        var admin = new TwoFactorAdminController(_users, _seeds, _invites, logger);
        admin.ControllerContext = new ControllerContext { HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext() };

        var result = Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(admin.CreateInvite(new AdminResetRequest { UserId = _ana.Id.ToString() }));
        var code = Assert.IsType<AdminInviteResponse>(result.Value).Code;

        Assert.NotEmpty(logger.Messages);
        Assert.DoesNotContain(logger.Messages, m => m.Contains(code, StringComparison.Ordinal));
        await Task.CompletedTask;
    }

    // ---- first administrator: start-up code ----

    private (BootstrapInviteService Service, CapturingLogger<BootstrapInviteService> Log) Bootstrap(params User[] users)
    {
        var manager = Substitute.For<IUserManager>();
        manager.GetUsers().Returns(users);
        var log = new CapturingLogger<BootstrapInviteService>();
        return (new BootstrapInviteService(manager, _seeds, _invites, log), log);
    }

    private static User Admin(string name)
    {
        var user = new User(name, "provider", "reset") { Id = Guid.NewGuid() };
        user.SetPermission(PermissionKind.IsAdministrator, true);
        return user;
    }

    [Fact]
    public void Startup_WithNoEnrolledAdmin_LogsOneCodePerAdmin_AndOnlyOnce()
    {
        var root = Admin("root");
        var second = Admin("segundo");
        var (service, log) = Bootstrap(root, second, _ana);

        Assert.True(service.TryIssue(TimeSpan.FromHours(24)));

        Assert.Equal(2, log.Messages.Count);
        Assert.All(log.Levels, level => Assert.Equal(LogLevel.Warning, level));
        var rootLine = Assert.Single(log.Messages, m => m.Contains("'root'"));
        var code = System.Text.RegularExpressions.Regex.Match(rootLine, @": ([A-Z2-9]{10}) \(").Groups[1].Value;
        Assert.NotNull(_invites.TryValidate(root.Id, code));
        Assert.Contains("valid until", rootLine);
        Assert.Null(_invites.GetActive(_ana.Id));

        // A second pass in the same run writes nothing.
        Assert.True(service.TryIssue(TimeSpan.FromHours(24)));
        Assert.Equal(2, log.Messages.Count);
    }

    [Fact]
    public void Startup_RegeneratesTheCodeOnEveryStart_WhileNoAdminIsEnrolled()
    {
        var root = Admin("root");
        var (first, firstLog) = Bootstrap(root);
        first.TryIssue(TimeSpan.FromHours(24));
        var oldCode = System.Text.RegularExpressions.Regex.Match(firstLog.Messages.Single(), @": ([A-Z2-9]{10}) \(").Groups[1].Value;

        var (second, secondLog) = Bootstrap(root);
        second.TryIssue(TimeSpan.FromHours(24));

        var newCode = System.Text.RegularExpressions.Regex.Match(secondLog.Messages.Single(), @": ([A-Z2-9]{10}) \(").Groups[1].Value;
        Assert.Null(_invites.TryValidate(root.Id, oldCode));
        Assert.NotNull(_invites.TryValidate(root.Id, newCode));
    }

    [Fact]
    public void Startup_WhenAnAdminIsEnrolled_WritesNoCode()
    {
        var root = Admin("root");
        var second = Admin("segundo");
        _seeds.TryEnroll(root.Id, TotpService.GenerateSecret(), 1, TotpOptions.Default);
        var (service, log) = Bootstrap(root, second, _ana);

        Assert.True(service.TryIssue(TimeSpan.FromHours(24)));

        Assert.Empty(log.Messages);
        Assert.Null(_invites.GetActive(second.Id));
    }

    [Fact]
    public void Startup_WhenTheUserListIsNotLoadedYet_AsksToRetry()
    {
        var (service, log) = Bootstrap();

        Assert.False(service.TryIssue(TimeSpan.FromHours(24)));
        Assert.Empty(log.Messages);
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = new();

        public List<LogLevel> Levels { get; } = new();

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
            Levels.Add(logLevel);
        }
    }

    private sealed class StandInAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public StandInAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(AdminHeader, out var role))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var claims = new List<Claim> { new("Jellyfin-UserId", Guid.NewGuid().ToString()), new("Jellyfin-Token", "t") };
            if (role == "admin")
            {
                claims.Add(new Claim("admin", "true"));
            }

            var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, "test")), "test");
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}
