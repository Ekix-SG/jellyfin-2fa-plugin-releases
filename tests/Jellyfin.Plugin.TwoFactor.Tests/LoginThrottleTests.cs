using Jellyfin.Plugin.TwoFactor.Tickets;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public class LoginThrottleTests
{
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private readonly Clock _clock = new();

    private LoginThrottle Create() => new(_clock);

    [Fact]
    public void Ip_IsBlockedAfterTheLimit_AndOnlyThatIp()
    {
        var throttle = Create();
        for (var i = 0; i < LoginThrottle.MaxFailuresPerIp - 1; i++)
        {
            throttle.RegisterFailure("1.1.1.1", null);
        }

        Assert.False(throttle.IsBlocked("1.1.1.1", null));
        throttle.RegisterFailure("1.1.1.1", null);
        Assert.True(throttle.IsBlocked("1.1.1.1", null));
        Assert.False(throttle.IsBlocked("2.2.2.2", null));
    }

    [Fact]
    public void Block_EndsWhenTheFailuresLeaveTheWindow()
    {
        var throttle = Create();
        for (var i = 0; i < LoginThrottle.MaxFailuresPerIp; i++)
        {
            throttle.RegisterFailure("1.1.1.1", null);
        }

        Assert.True(throttle.IsBlocked("1.1.1.1", null));
        _clock.Now += LoginThrottle.Window - TimeSpan.FromSeconds(1);
        Assert.True(throttle.IsBlocked("1.1.1.1", null));
        _clock.Now += TimeSpan.FromSeconds(1);
        Assert.False(throttle.IsBlocked("1.1.1.1", null));
    }

    [Fact]
    public void User_IsBlockedFromAnyIp_CaseInsensitively_WithAHigherLimit()
    {
        var throttle = Create();
        for (var i = 0; i < LoginThrottle.MaxFailuresPerUser; i++)
        {
            throttle.RegisterFailure("10.0.0." + i, i % 2 == 0 ? "Ana" : "ANA ");
        }

        Assert.True(throttle.IsBlocked("9.9.9.9", "ana"));
        Assert.False(throttle.IsBlocked("9.9.9.9", "luis"));
        Assert.False(throttle.IsBlocked("9.9.9.9", null));
    }

    [Fact]
    public void Success_ClearsTheUserCounter_ButNotTheIpOne()
    {
        var throttle = Create();
        for (var i = 0; i < LoginThrottle.MaxFailuresPerUser; i++)
        {
            throttle.RegisterFailure("10.0.0." + i, "ana");
        }

        Assert.True(throttle.IsBlocked("9.9.9.9", "ana"));
        throttle.RegisterSuccess("Ana");
        Assert.False(throttle.IsBlocked("9.9.9.9", "ana"));

        for (var i = 0; i < LoginThrottle.MaxFailuresPerIp; i++)
        {
            throttle.RegisterFailure("5.5.5.5", "ana");
        }

        throttle.RegisterSuccess("ana");
        Assert.True(throttle.IsBlocked("5.5.5.5", "ana"));
    }
}
