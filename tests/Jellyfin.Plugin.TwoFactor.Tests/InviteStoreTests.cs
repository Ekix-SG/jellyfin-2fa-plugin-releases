using System.Security.Cryptography;
using Jellyfin.Plugin.TwoFactor.Configuration;
using Jellyfin.Plugin.TwoFactor.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public sealed class InviteStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tf-invites-" + Guid.NewGuid().ToString("N"));
    private readonly SeedCipher _cipher = new(RandomNumberGenerator.GetBytes(32));
    private readonly FakeTimeProvider _time = new(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    private FileInviteStore Open() => new(_dir, _cipher, _time, NullLogger.Instance);

    [Fact]
    public void Code_HasTenCharacters_FromTheUnambiguousAlphabet()
    {
        var store = Open();
        for (var i = 0; i < 200; i++)
        {
            var code = store.Create(Guid.NewGuid(), TimeSpan.FromHours(1)).Code;
            Assert.Equal(10, code.Length);
            Assert.All(code, c => Assert.Contains(c, "ABCDEFGHJKMNPQRSTUVWXYZ23456789"));
            Assert.DoesNotContain(code, c => "0O1IL".Contains(c));
        }
    }

    [Fact]
    public void Code_IsValidOnlyForItsUser()
    {
        var store = Open();
        var ana = Guid.NewGuid();
        var invite = store.Create(ana, TimeSpan.FromHours(1));

        Assert.Equal(invite.InviteId, store.TryValidate(ana, invite.Code));
        Assert.Null(store.TryValidate(Guid.NewGuid(), invite.Code));
        Assert.Null(store.TryValidate(ana, null));
        Assert.Null(store.TryValidate(ana, "AAAAAAAAAA"));
    }

    [Fact]
    public void Code_IgnoresCaseSpacesAndHyphens()
    {
        var store = Open();
        var ana = Guid.NewGuid();
        var code = store.Create(ana, TimeSpan.FromHours(1)).Code;

        Assert.NotNull(store.TryValidate(ana, code.ToLowerInvariant()));
        Assert.NotNull(store.TryValidate(ana, code[..5] + "-" + code[5..]));
        Assert.NotNull(store.TryValidate(ana, " " + code + " "));
    }

    [Fact]
    public void Code_Expires()
    {
        var store = Open();
        var ana = Guid.NewGuid();
        var invite = store.Create(ana, TimeSpan.FromHours(24));

        _time.Advance(TimeSpan.FromHours(23));
        Assert.NotNull(store.TryValidate(ana, invite.Code));

        _time.Advance(TimeSpan.FromHours(2));
        Assert.Null(store.TryValidate(ana, invite.Code));
        Assert.Null(store.GetActive(ana));
        Assert.False(store.IsActive(invite.InviteId));
    }

    [Fact]
    public void Code_IsSingleUse()
    {
        var store = Open();
        var ana = Guid.NewGuid();
        var invite = store.Create(ana, TimeSpan.FromHours(1));

        Assert.True(store.Consume(invite.InviteId));
        Assert.False(store.Consume(invite.InviteId));
        Assert.Null(store.TryValidate(ana, invite.Code));
    }

    [Fact]
    public void ANewCode_InvalidatesThePreviousOne()
    {
        var store = Open();
        var ana = Guid.NewGuid();
        var first = store.Create(ana, TimeSpan.FromHours(1));
        var second = store.Create(ana, TimeSpan.FromHours(1));

        Assert.Null(store.TryValidate(ana, first.Code));
        Assert.False(store.IsActive(first.InviteId));
        Assert.Equal(second.InviteId, store.TryValidate(ana, second.Code));
    }

    [Fact]
    public void FiveFailures_InvalidateTheCode_EvenIfTheNextOneIsRight()
    {
        var store = Open();
        var ana = Guid.NewGuid();
        var invite = store.Create(ana, TimeSpan.FromHours(1));

        for (var i = 0; i < FileInviteStore.MaxFailedAttempts - 1; i++)
        {
            store.RegisterFailure(ana);
        }

        Assert.NotNull(store.TryValidate(ana, invite.Code));
        store.RegisterFailure(ana);

        Assert.Null(store.TryValidate(ana, invite.Code));
        Assert.Null(store.GetActive(ana));
    }

    [Fact]
    public void Revoke_DeletesTheCode()
    {
        var store = Open();
        var ana = Guid.NewGuid();
        var invite = store.Create(ana, TimeSpan.FromHours(1));

        Assert.True(store.Revoke(ana));
        Assert.False(store.Revoke(ana));
        Assert.Null(store.TryValidate(ana, invite.Code));
    }

    [Fact]
    public void State_SurvivesAReload_IncludingTheFailureCounter()
    {
        var store = Open();
        var ana = Guid.NewGuid();
        var invite = store.Create(ana, TimeSpan.FromHours(1));
        for (var i = 0; i < FileInviteStore.MaxFailedAttempts - 1; i++)
        {
            store.RegisterFailure(ana);
        }

        var reloaded = Open();
        Assert.Equal(invite.InviteId, reloaded.TryValidate(ana, invite.Code));
        reloaded.RegisterFailure(ana);
        Assert.Null(Open().TryValidate(ana, invite.Code));
    }

    [Fact]
    public void TheFile_DoesNotContainThePlainCode()
    {
        var store = Open();
        var ana = Guid.NewGuid();
        var code = store.Create(ana, TimeSpan.FromHours(1)).Code;

        var text = File.ReadAllText(Path.Combine(_dir, "invites.json"));
        Assert.DoesNotContain(code, text);
    }

    [Fact]
    public void WithoutAKey_TheStoreIsUnavailable_AndWritesNothing()
    {
        var store = new FileInviteStore(_dir, null, _time, NullLogger.Instance);

        Assert.False(store.IsAvailable);
        Assert.Throws<InvalidOperationException>(() => store.Create(Guid.NewGuid(), TimeSpan.FromHours(1)));
        Assert.False(File.Exists(Path.Combine(_dir, "invites.json")));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(-5, 1)]
    [InlineData(24, 24)]
    [InlineData(168, 168)]
    [InlineData(1000, 168)]
    public void InviteTtl_IsClampedToOneHourAndOneWeek(int configured, int expectedHours)
    {
        var config = new PluginConfiguration { InviteTtlHours = configured };
        Assert.Equal(TimeSpan.FromHours(expectedHours), config.InviteTtl);
        Assert.Equal(24, new PluginConfiguration().InviteTtlHours);
    }
}
