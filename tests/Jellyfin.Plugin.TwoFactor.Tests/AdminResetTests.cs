using System.Security.Claims;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactor.Api;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Tickets;
using Jellyfin.Plugin.TwoFactor.Totp;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public class AdminResetTests
{
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly ISeedStore _seeds = Substitute.For<ISeedStore>();
    private readonly ISessionManager _sessions = Substitute.For<ISessionManager>();
    private readonly Guid _admin = Guid.NewGuid();
    private readonly User _target = new("ana", "provider", "reset") { Id = Guid.NewGuid() };

    private TwoFactorManageController Create(Guid callerId)
    {
        _seeds.IsAvailable.Returns(true);
        _seeds.Remove(Arg.Any<Guid>()).Returns(true);
        _users.GetUserById(_target.Id).Returns(_target);
        _users.GetUserById(_admin).Returns(new User("root", "provider", "reset") { Id = _admin });
        var context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                new[] { new Claim("Jellyfin-UserId", callerId.ToString()), new Claim("Jellyfin-Token", "admin-token") },
                "test"))
        };
        return new TwoFactorManageController(
            _users,
            _seeds,
            Substitute.For<IInviteStore>(),
            new TotpSettings(TotpOptions.Default, true),
            new TicketStore(TimeProvider.System),
            new LoginThrottle(TimeProvider.System),
            _sessions,
            TimeProvider.System,
            NullLogger<TwoFactorManageController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };
    }

    [Fact]
    public async Task Reset_OfAnotherUser_DeletesTheSeed_AndRevokesAllTheirTokens()
    {
        var result = await Create(_admin).AdminReset(new AdminResetRequest { UserId = _target.Id.ToString() });

        Assert.IsType<OkObjectResult>(result);
        _seeds.Received(1).Remove(_target.Id);
        await _sessions.Received(1).RevokeUserTokens(_target.Id, string.Empty);
    }

    [Fact]
    public async Task Reset_OfTheAdminThemselves_KeepsTheCurrentSession()
    {
        _users.GetUserById(_admin).Returns(new User("root", "provider", "reset") { Id = _admin });
        var controller = Create(_admin);
        _users.GetUserByName("root").Returns(new User("root", "provider", "reset") { Id = _admin });

        await controller.AdminReset(new AdminResetRequest { Username = "root" });

        await _sessions.Received(1).RevokeUserTokens(_admin, "admin-token");
    }

    [Fact]
    public async Task Reset_OfAnUnknownUser_ChangesNothing()
    {
        var result = await Create(_admin).AdminReset(new AdminResetRequest { Username = "nadie" });

        Assert.IsType<NotFoundObjectResult>(result);
        _seeds.DidNotReceiveWithAnyArgs().Remove(default);
        await _sessions.DidNotReceiveWithAnyArgs().RevokeUserTokens(default, default!);
    }
}
