using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactor.Api;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Tickets;
using Jellyfin.Plugin.TwoFactor.Totp;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Users;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public class ResetPasswordTests
{
    private readonly IUserManager _users = Substitute.For<IUserManager>();
    private readonly ISeedStore _seeds = Substitute.For<ISeedStore>();
    private readonly TwoFactorController _controller;

    public ResetPasswordTests()
    {
        _controller = new TwoFactorController(
            _users,
            Substitute.For<ISessionManager>(),
            _seeds,
            Substitute.For<IInviteStore>(),
            new TotpSettings(TotpOptions.Default, true),
            new TicketStore(TimeProvider.System),
            new LoginThrottle(TimeProvider.System),
            TimeProvider.System,
            NullLogger<TwoFactorController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
    }

    private static User NewUser(string name) => new(name, "provider", "reset") { Id = Guid.NewGuid() };

    private static int StatusOf(ActionResult result) => result switch
    {
        ObjectResult o => o.StatusCode ?? 200,
        StatusCodeResult s => s.StatusCode,
        _ => throw new InvalidOperationException(result.GetType().Name)
    };

    private static string MessageOf(ActionResult result) => ((ErrorResponse)((ObjectResult)result).Value!).Error;

    [Fact]
    public async Task ValidPin_SetsTheNewPassword_ForEachUserReset()
    {
        var ana = NewUser("ana");
        _users.RedeemPasswordResetPin("AB-CD-EF-01").Returns(new PinRedeemResult { Success = true, UsersReset = new[] { "ana" } });
        _users.GetUserByName("ana").Returns(ana);

        var result = await _controller.ResetPassword(new ResetPasswordRequest { Pin = "AB-CD-EF-01", NewPassword = "nueva-clave" });

        Assert.Equal(200, StatusOf(result));
        await _users.Received(1).ChangePassword(ana.Id, "nueva-clave");
    }

    [Fact]
    public async Task ValidPin_NeverTouchesTheSeeds()
    {
        _users.RedeemPasswordResetPin(Arg.Any<string>()).Returns(new PinRedeemResult { Success = true, UsersReset = new[] { "ana" } });
        _users.GetUserByName("ana").Returns(NewUser("ana"));

        await _controller.ResetPassword(new ResetPasswordRequest { Pin = "AB-CD-EF-01", NewPassword = "x" });

        _seeds.DidNotReceiveWithAnyArgs().TryEnroll(default, default!, default, default!);
        _seeds.DidNotReceiveWithAnyArgs().TryAcceptCode(default, default, default);
    }

    [Theory]
    [InlineData(null, "nueva")]
    [InlineData("", "nueva")]
    [InlineData("   ", "nueva")]
    [InlineData("AB-CD-EF-01", null)]
    [InlineData("AB-CD-EF-01", "")]
    public async Task InvalidInput_IsRejected_BeforeThePinIsRedeemed(string? pin, string? password)
    {
        var result = await _controller.ResetPassword(new ResetPasswordRequest { Pin = pin, NewPassword = password });

        Assert.Equal(401, StatusOf(result));
        await _users.DidNotReceiveWithAnyArgs().RedeemPasswordResetPin(default!);
        await _users.DidNotReceiveWithAnyArgs().ChangePassword(default, default!);
    }

    [Fact]
    public async Task TooLongInput_IsRejected_BeforeThePinIsRedeemed()
    {
        var result = await _controller.ResetPassword(new ResetPasswordRequest { Pin = "AB-CD-EF-01", NewPassword = new string('x', 257) });

        Assert.Equal(401, StatusOf(result));
        await _users.DidNotReceiveWithAnyArgs().RedeemPasswordResetPin(default!);
    }

    [Fact]
    public async Task UnknownPin_GivesTheUniformError_AndChangesNothing()
    {
        _users.RedeemPasswordResetPin("MAL").Returns<PinRedeemResult>(_ => throw new MediaBrowser.Common.Extensions.ResourceNotFoundException("no pin"));

        var result = await _controller.ResetPassword(new ResetPasswordRequest { Pin = "MAL", NewPassword = "nueva" });

        Assert.Equal(401, StatusOf(result));
        Assert.Equal("PIN incorrecto o caducado.", MessageOf(result));
        await _users.DidNotReceiveWithAnyArgs().ChangePassword(default, default!);
    }

    [Fact]
    public async Task UnsuccessfulRedeem_ChangesNothing()
    {
        _users.RedeemPasswordResetPin(Arg.Any<string>()).Returns(new PinRedeemResult { Success = false });

        var result = await _controller.ResetPassword(new ResetPasswordRequest { Pin = "AB-CD-EF-01", NewPassword = "nueva" });

        Assert.Equal(401, StatusOf(result));
        await _users.DidNotReceiveWithAnyArgs().ChangePassword(default, default!);
    }

    [Fact]
    public async Task FailureWhileChangingThePassword_IsReportedWithoutLeakingDetails()
    {
        var ana = NewUser("ana");
        _users.RedeemPasswordResetPin(Arg.Any<string>()).Returns(new PinRedeemResult { Success = true, UsersReset = new[] { "ana" } });
        _users.GetUserByName("ana").Returns(ana);
        _users.ChangePassword(ana.Id, Arg.Any<string>()).Returns<Task>(_ => throw new InvalidOperationException("secret detail"));

        var result = await _controller.ResetPassword(new ResetPasswordRequest { Pin = "AB-CD-EF-01", NewPassword = "nueva" });

        Assert.Equal(401, StatusOf(result));
        Assert.DoesNotContain("secret detail", MessageOf(result));
    }
}
