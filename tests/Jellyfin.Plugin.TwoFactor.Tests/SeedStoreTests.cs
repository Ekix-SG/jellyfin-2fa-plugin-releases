using System.Security.Cryptography;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Totp;
using Microsoft.Extensions.Logging.Abstractions;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public sealed class SeedStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tf-tests-" + Guid.NewGuid().ToString("N"));
    private readonly DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
    private readonly SeedCipher _cipher = new(RandomNumberGenerator.GetBytes(32));

    private string SeedsPath => Path.Combine(_dir, "seeds.json");

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    private FileSeedStore Open(SeedCipher? cipher = null, bool noKey = false)
        => new(_dir, noKey ? null : cipher ?? _cipher, NullLogger.Instance);

    [Fact]
    public void Enroll_ThenAcceptCode_ThenReplayIsRejected()
    {
        var store = Open();
        var user = Guid.NewGuid();
        var secret = TotpService.GenerateSecret();
        var counter = TotpService.GetCounter(_now);

        Assert.False(store.IsEnabled(user));
        Assert.True(store.TryEnroll(user, secret, counter, TotpOptions.Default));
        Assert.True(store.IsEnabled(user));

        // The confirmation code (counter) is burnt; the next step is accepted once.
        var next = TotpService.ComputeCode(secret, counter + 1);
        Assert.False(store.TryAcceptCode(user, TotpService.ComputeCode(secret, counter), _now));
        Assert.True(store.TryAcceptCode(user, next, _now.AddSeconds(30)));
        Assert.False(store.TryAcceptCode(user, next, _now.AddSeconds(30)));
    }

    [Fact]
    public void State_SurvivesReload_IncludingLastCounter()
    {
        var user = Guid.NewGuid();
        var secret = TotpService.GenerateSecret();
        var counter = TotpService.GetCounter(_now);
        var first = Open();
        first.TryEnroll(user, secret, counter - 5, TotpOptions.Default);
        var code = TotpService.ComputeCode(secret, counter);
        Assert.True(first.TryAcceptCode(user, code, _now));

        var second = Open();
        Assert.True(second.IsEnabled(user));
        Assert.False(second.TryAcceptCode(user, code, _now));
    }

    [Fact]
    public void Enroll_FailsIfAlreadyEnabled_AndKeepsOriginalSecret()
    {
        var store = Open();
        var user = Guid.NewGuid();
        var original = TotpService.GenerateSecret();
        var other = TotpService.GenerateSecret();
        Assert.True(store.TryEnroll(user, original, -1, TotpOptions.Default));
        Assert.False(store.TryEnroll(user, other, -1, TotpOptions.Default));
        Assert.True(store.TryAcceptCode(user, TotpService.ComputeCode(original, TotpService.GetCounter(_now)), _now));
    }

    [Fact]
    public void UnknownUser_IsRejected()
    {
        var store = Open();
        Assert.False(store.TryAcceptCode(Guid.NewGuid(), "123456", _now));
    }

    [Fact]
    public void Save_LeavesNoTemporaryFile()
    {
        var store = Open();
        store.TryEnroll(Guid.NewGuid(), TotpService.GenerateSecret(), -1, TotpOptions.Default);
        Assert.True(File.Exists(SeedsPath));
        Assert.False(File.Exists(SeedsPath + ".tmp"));
    }

    [Fact]
    public void FileOnDisk_ContainsNoPlainTextSecretOrState()
    {
        var store = Open();
        var user = Guid.NewGuid();
        var secret = TotpService.GenerateSecret();
        store.TryEnroll(user, secret, 123456789, TotpOptions.Default);

        var text = File.ReadAllText(SeedsPath);
        Assert.DoesNotContain(Base32.Encode(secret), text);
        Assert.DoesNotContain("secret", text);
        Assert.DoesNotContain("lastCounter", text);
        Assert.DoesNotContain("123456789", text);
        Assert.DoesNotContain("enabled", text);
        Assert.Contains("\"version\": 2", text);
    }

    [Fact]
    public void WrongKey_LocksTheUsersOut_AndTheyCannotReEnroll()
    {
        var user = Guid.NewGuid();
        var secret = TotpService.GenerateSecret();
        Open().TryEnroll(user, secret, -1, TotpOptions.Default);

        var wrong = Open(new SeedCipher(RandomNumberGenerator.GetBytes(32)));
        Assert.True(wrong.IsEnabled(user));
        Assert.False(wrong.TryAcceptCode(user, TotpService.ComputeCode(secret, TotpService.GetCounter(_now)), _now));
        Assert.False(wrong.TryEnroll(user, TotpService.GenerateSecret(), -1, TotpOptions.Default));
    }

    [Fact]
    public void WrongKey_KeepsUnreadableEntriesWhenSavingOthers_SoTheRightKeyStillWorks()
    {
        var user = Guid.NewGuid();
        var secret = TotpService.GenerateSecret();
        Open().TryEnroll(user, secret, -1, TotpOptions.Default);

        var wrong = Open(new SeedCipher(RandomNumberGenerator.GetBytes(32)));
        Assert.True(wrong.TryEnroll(Guid.NewGuid(), TotpService.GenerateSecret(), -1, TotpOptions.Default));

        var original = Open();
        Assert.True(original.TryAcceptCode(user, TotpService.ComputeCode(secret, TotpService.GetCounter(_now)), _now));
    }

    [Fact]
    public void EntryMovedToAnotherUserId_IsNotAccepted()
    {
        var alice = Guid.NewGuid();
        var mallory = Guid.NewGuid();
        var secret = TotpService.GenerateSecret();
        Open().TryEnroll(alice, secret, -1, TotpOptions.Default);

        var json = JsonDocument.Parse(File.ReadAllText(SeedsPath)).RootElement;
        var data = json.GetProperty("users")[0].GetProperty("data").GetString();
        File.WriteAllText(SeedsPath, JsonSerializer.Serialize(new
        {
            version = 2,
            users = new[] { new { userId = mallory, data } }
        }));

        var store = Open();
        Assert.False(store.TryAcceptCode(mallory, TotpService.ComputeCode(secret, TotpService.GetCounter(_now)), _now));
    }

    [Fact]
    public void TamperedFile_IsNotAccepted()
    {
        var user = Guid.NewGuid();
        var secret = TotpService.GenerateSecret();
        Open().TryEnroll(user, secret, -1, TotpOptions.Default);

        var raw = Convert.FromBase64String(
            JsonDocument.Parse(File.ReadAllText(SeedsPath)).RootElement.GetProperty("users")[0].GetProperty("data").GetString()!);
        raw[^1] ^= 0x01;
        File.WriteAllText(SeedsPath, JsonSerializer.Serialize(new
        {
            version = 2,
            users = new[] { new { userId = user, data = Convert.ToBase64String(raw) } }
        }));

        var store = Open();
        Assert.True(store.IsEnabled(user));
        Assert.False(store.TryAcceptCode(user, TotpService.ComputeCode(secret, TotpService.GetCounter(_now)), _now));
    }

    [Fact]
    public void LegacyPlainTextFile_IsMigratedToEncrypted_AndStillWorks()
    {
        var user = Guid.NewGuid();
        var secret = TotpService.GenerateSecret();
        Directory.CreateDirectory(_dir);
        File.WriteAllText(SeedsPath, JsonSerializer.Serialize(new
        {
            users = new[] { new { userId = user, secret = Base32.Encode(secret), enabled = true, lastCounter = -1L } }
        }));

        var store = Open();
        Assert.True(store.IsEnabled(user));

        var text = File.ReadAllText(SeedsPath);
        Assert.DoesNotContain(Base32.Encode(secret), text);
        Assert.Contains("\"version\": 2", text);
        Assert.False(File.Exists(SeedsPath + ".tmp"));

        var reopened = Open();
        Assert.True(reopened.TryAcceptCode(user, TotpService.ComputeCode(secret, TotpService.GetCounter(_now)), _now));
    }

    [Fact]
    public void NoKey_StoreIsUnavailable_AndTheExistingFileIsNotTouched()
    {
        var user = Guid.NewGuid();
        var legacy = JsonSerializer.Serialize(new
        {
            users = new[] { new { userId = user, secret = "JBSWY3DPEHPK3PXP", enabled = true, lastCounter = -1L } }
        });
        Directory.CreateDirectory(_dir);
        File.WriteAllText(SeedsPath, legacy);
        var before = File.ReadAllBytes(SeedsPath);

        var store = Open(noKey: true);
        Assert.False(store.IsAvailable);
        Assert.Throws<InvalidOperationException>(() => store.IsEnabled(user));
        Assert.Throws<InvalidOperationException>(() => store.TryEnroll(user, TotpService.GenerateSecret(), -1, TotpOptions.Default));
        Assert.Throws<InvalidOperationException>(() => store.TryAcceptCode(user, "123456", _now));

        Assert.Equal(before, File.ReadAllBytes(SeedsPath));
        Assert.False(File.Exists(SeedsPath + ".tmp"));
    }

    [Fact]
    public void NoKey_NoFile_NothingIsCreated()
    {
        var store = Open(noKey: true);
        Assert.False(store.IsAvailable);
        Assert.False(File.Exists(SeedsPath));
    }
}
