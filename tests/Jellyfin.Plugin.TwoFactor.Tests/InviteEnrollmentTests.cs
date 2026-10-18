using System.Security.Claims;
using System.Security.Cryptography;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactor.Api;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Tickets;
using Jellyfin.Plugin.TwoFactor.Totp;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Jellyfin.Plugin.TwoFactor.Tests;

/// <summary>The enrollment flow end to end, with the real stores and a mocked Jellyfin.</summary>
public sealed class InviteEnrollmentTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tf-enroll-" + Guid.NewGuid().ToString("N"));
    private readonly FakeTimeProvider _time = new(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
    private readonly SeedCipher _cipher = new(RandomNumberGenerator.GetBytes(32));
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly ISessionManager _sessions = Substitute.For<ISessionManager>();
    private readonly User _ana = new("ana", "provider", "reset") { Id = Guid.NewGuid() };
    private readonly User _beto = new("beto", "provider", "reset") { Id = Guid.NewGuid() };
    private readonly FileSeedStore _seeds;
    private readonly FileInviteStore _invites;
    private readonly TicketStore _tickets;
    private readonly LoginThrottle _throttle;
    private readonly TwoFactorController _controller;

    public InviteEnrollmentTests()
    {
        _seeds = new FileSeedStore(_dir, _cipher, NullLogger.Instance);
        _invites = new FileInviteStore(_dir, _cipher, _time, NullLogger.Instance);
        _tickets = new TicketStore(_time);
        _throttle = new LoginThrottle(_time);
        _users.AuthenticateUser("ana", Arg.Any<string>(), Arg.Any<string>(), Arg.Any<bool>()).Returns(_ana);
        _users.AuthenticateUser("beto", Arg.Any<string>(), Arg.Any<string>(), Arg.Any<bool>()).Returns(_beto);
        _users.GetUserById(_ana.Id).Returns(_ana);
        _sessions.AuthenticateDirect(Arg.Any<AuthenticationRequest>()).Returns(ci => new AuthenticationResult
        {
            User = new MediaBrowser.Model.Dto.UserDto { Id = ci.Arg<AuthenticationRequest>().UserId, Name = "u" },
            AccessToken = "token",
            ServerId = "server"
        });
        _controller = new TwoFactorController(
            _users,
            _sessions,
            _seeds,
            _invites,
            new TotpSettings(TotpOptions.Default, true),
            _tickets,
            _throttle,
            _time,
            NullLogger<TwoFactorController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    private async Task<string> Step1(string name = "ana", string password = "pw")
    {
        var result = await _controller.Step1(new Step1Request { Username = name, Password = password, DeviceId = "dev" });
        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<Step1Response>(ok.Value);
        Assert.True(response.NeedsEnrollment);
        return response.Ticket;
    }

    private ActionResult Begin(string ticket, string? invite) =>
        _controller.EnrollBegin(new EnrollBeginRequest { Ticket = ticket, DeviceId = "dev", InviteCode = invite });

    private Task<ActionResult> Confirm(string ticket, string code) =>
        _controller.EnrollConfirm(new CodeRequest { Ticket = ticket, DeviceId = "dev", Code = code });

    private static void AssertUniform(ActionResult result)
    {
        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(401, unauthorized.StatusCode);
        Assert.Equal(new ErrorResponse().Error, Assert.IsType<ErrorResponse>(unauthorized.Value).Error);
    }

    private Ticket TicketOf(string token) => _tickets.Get(token, "127.0.0.1", "dev")!;

    private string CorrectTotp(Ticket ticket) => TotpService.ComputeCode(ticket.PendingSecret!, TotpService.GetCounter(_time.GetUtcNow()));

    [Fact]
    public async Task Begin_WithoutACode_IsRefused_AndCreatesNoPendingSecret()
    {
        var ticket = await Step1();

        AssertUniform(Begin(ticket, null));
        AssertUniform(Begin(ticket, string.Empty));

        Assert.Null(TicketOf(ticket).PendingSecret);
    }

    [Fact]
    public async Task Begin_WithAnotherUsersCode_IsRefused_AndCreatesNoPendingSecret()
    {
        var betoCode = _invites.Create(_beto.Id, TimeSpan.FromHours(24)).Code;
        _invites.Create(_ana.Id, TimeSpan.FromHours(24));
        var ticket = await Step1();

        AssertUniform(Begin(ticket, betoCode));

        Assert.Null(TicketOf(ticket).PendingSecret);
        Assert.NotNull(_invites.GetActive(_beto.Id));
    }

    [Fact]
    public async Task Begin_WithAnExpiredCode_IsRefused()
    {
        var code = _invites.Create(_ana.Id, TimeSpan.FromHours(24)).Code;
        _time.Advance(TimeSpan.FromHours(25));
        var ticket = await Step1();

        AssertUniform(Begin(ticket, code));

        Assert.Null(TicketOf(ticket).PendingSecret);
    }

    [Fact]
    public async Task Begin_WithAReusedCode_IsRefused()
    {
        var code = _invites.Create(_ana.Id, TimeSpan.FromHours(24)).Code;
        var first = await Step1();
        Assert.IsType<OkObjectResult>(Begin(first, code));
        Assert.IsType<OkObjectResult>(await Confirm(first, CorrectTotp(TicketOf(first))));

        // The administrator resets the user without generating a new code: the old one is gone.
        _seeds.Remove(_ana.Id);
        var second = await Step1();

        AssertUniform(Begin(second, code));
        Assert.Null(TicketOf(second).PendingSecret);
    }

    [Fact]
    public async Task EveryFailure_GivesTheSameStatusAndBody()
    {
        var anaCode = _invites.Create(_ana.Id, TimeSpan.FromHours(24)).Code;
        var betoCode = _invites.Create(_beto.Id, TimeSpan.FromHours(24)).Code;
        var ticket = await Step1();

        var results = new[]
        {
            Begin(ticket, null),
            Begin(ticket, "AAAAAAAAAA"),
            Begin(ticket, betoCode),
            Begin("no-such-ticket", anaCode),
            _controller.EnrollBegin(new EnrollBeginRequest { Ticket = ticket, DeviceId = "other-device", InviteCode = anaCode })
        };

        Assert.All(results, AssertUniform);
        Assert.Single(results.Select(r => ((UnauthorizedObjectResult)r).StatusCode).Distinct());
        Assert.Single(results.Select(r => ((ErrorResponse)((UnauthorizedObjectResult)r).Value!).Error).Distinct());
    }

    [Fact]
    public async Task Confirm_WithoutHavingAcceptedACode_IsRefused()
    {
        _invites.Create(_ana.Id, TimeSpan.FromHours(24));
        var ticket = await Step1();
        // Begin never succeeded, so there is no pending secret and no accepted code on the ticket.
        AssertUniform(await Confirm(ticket, "123456"));
        Assert.False(_seeds.IsEnabled(_ana.Id));
    }

    [Fact]
    public async Task FiveWrongCodes_InvalidateIt_EvenIfTheNextIsRight()
    {
        var code = _invites.Create(_ana.Id, TimeSpan.FromHours(24)).Code;

        for (var i = 0; i < FileInviteStore.MaxFailedAttempts; i++)
        {
            // A fresh ticket each time: the ticket itself also dies after five failures.
            AssertUniform(Begin(await Step1(), "BBBBBBBBBB"));
        }

        var ticket = await Step1();
        AssertUniform(Begin(ticket, code));
        Assert.Null(TicketOf(ticket).PendingSecret);
        Assert.Null(_invites.GetActive(_ana.Id));
    }

    [Fact]
    public async Task WrongTotp_ThenRight_ConsumesTheCodeOnlyAtTheEnd()
    {
        var invite = _invites.Create(_ana.Id, TimeSpan.FromHours(24));
        var ticket = await Step1();

        Assert.IsType<OkObjectResult>(Begin(ticket, invite.Code));
        Assert.True(_invites.IsActive(invite.InviteId));

        AssertUniform(await Confirm(ticket, "000000"));
        Assert.True(_invites.IsActive(invite.InviteId));
        Assert.False(_seeds.IsEnabled(_ana.Id));

        // Retry with the same ticket and the right code.
        Assert.IsType<OkObjectResult>(Begin(ticket, invite.Code));
        Assert.IsType<OkObjectResult>(await Confirm(ticket, CorrectTotp(TicketOf(ticket))));

        Assert.False(_invites.IsActive(invite.InviteId));
        Assert.True(_seeds.IsEnabled(_ana.Id));
    }

    [Fact]
    public async Task ARevokedCode_StopsAnEnrollmentThatAlreadyBegan()
    {
        var invite = _invites.Create(_ana.Id, TimeSpan.FromHours(24));
        var ticket = await Step1();
        Assert.IsType<OkObjectResult>(Begin(ticket, invite.Code));

        _invites.Revoke(_ana.Id);

        AssertUniform(await Confirm(ticket, CorrectTotp(TicketOf(ticket))));
        Assert.False(_seeds.IsEnabled(_ana.Id));
    }

    [Fact]
    public async Task ANewCode_InvalidatesTheOldOne_BeforeBegin()
    {
        var old = _invites.Create(_ana.Id, TimeSpan.FromHours(24));
        var fresh = _invites.Create(_ana.Id, TimeSpan.FromHours(24));
        var ticket = await Step1();

        AssertUniform(Begin(ticket, old.Code));
        Assert.IsType<OkObjectResult>(Begin(ticket, fresh.Code));
    }

    [Fact]
    public async Task AccountsWithAnEmptyPassword_NeedTheCodeToo()
    {
        var ticket = await Step1(password: string.Empty);

        AssertUniform(Begin(ticket, null));
        Assert.Null(TicketOf(ticket).PendingSecret);
    }

    [Fact]
    public async Task WithoutSeedAndWithoutCode_ThereIsNeverASession()
    {
        var ticket = await Step1();

        AssertUniform(Begin(ticket, null));
        AssertUniform(await Confirm(ticket, "123456"));
        AssertUniform(await _controller.Step2(new CodeRequest { Ticket = ticket, DeviceId = "dev", Code = "123456" }));

        await _sessions.DidNotReceiveWithAnyArgs().AuthenticateDirect(default!);
    }

    [Fact]
    public async Task AdminReset_DeletesTheSeed_AndTheUserNeedsANewCode()
    {
        var invite = _invites.Create(_ana.Id, TimeSpan.FromHours(24));
        var first = await Step1();
        Assert.IsType<OkObjectResult>(Begin(first, invite.Code));
        Assert.IsType<OkObjectResult>(await Confirm(first, CorrectTotp(TicketOf(first))));
        var stale = _invites.Create(_ana.Id, TimeSpan.FromHours(24)); // an unused code from before the reset

        var admin = new User("root", "provider", "reset") { Id = Guid.NewGuid() };
        _users.GetUserById(admin.Id).Returns(admin);
        var manage = new TwoFactorManageController(
            _users,
            _seeds,
            _invites,
            new TotpSettings(TotpOptions.Default, true),
            _tickets,
            _throttle,
            _sessions,
            _time,
            NullLogger<TwoFactorManageController>.Instance)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity(
                        new[] { new Claim("Jellyfin-UserId", admin.Id.ToString()), new Claim("Jellyfin-Token", "t") }, "test"))
                }
            }
        };

        Assert.IsType<OkObjectResult>(await manage.AdminReset(new AdminResetRequest { UserId = _ana.Id.ToString() }));
        Assert.False(_seeds.IsEnabled(_ana.Id));

        // Back to the start: password alone gives an enrollment ticket, and without a new code it leads nowhere.
        var ticket = await Step1();
        AssertUniform(Begin(ticket, stale.Code));
        AssertUniform(Begin(ticket, invite.Code));
        Assert.Null(TicketOf(ticket).PendingSecret);

        var fresh = _invites.Create(_ana.Id, TimeSpan.FromHours(24));
        Assert.IsType<OkObjectResult>(Begin(await Step1(), fresh.Code));
    }
}
