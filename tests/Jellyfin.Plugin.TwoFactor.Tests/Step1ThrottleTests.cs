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

public class Step1ThrottleTests
{
    [Fact]
    public async Task Step1_FromABlockedIp_IsRefused_WithoutCheckingThePassword()
    {
        var users = Substitute.For<IUserManager>();
        var seeds = Substitute.For<ISeedStore>();
        seeds.IsAvailable.Returns(true);
        var throttle = new LoginThrottle(TimeProvider.System);
        var controller = new TwoFactorController(
            users,
            Substitute.For<ISessionManager>(),
            seeds,
            Substitute.For<IInviteStore>(),
            new TotpSettings(TotpOptions.Default, true),
            new TicketStore(TimeProvider.System),
            throttle,
            TimeProvider.System,
            NullLogger<TwoFactorController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
        const string ip = "127.0.0.1"; // what GetNormalizedRemoteIP returns for a context without a remote address
        for (var i = 0; i < LoginThrottle.MaxFailuresPerIp; i++)
        {
            throttle.RegisterFailure(ip, null);
        }

        var result = await controller.Step1(new Step1Request { Username = "ana", Password = "x", DeviceId = "d" });

        Assert.IsType<UnauthorizedObjectResult>(result);
        await users.DidNotReceiveWithAnyArgs().AuthenticateUser(default!, default!, default!, default);
    }
}
