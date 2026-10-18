using System.Text;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Totp;
using Microsoft.Extensions.Logging.Abstractions;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public sealed class TotpOptionsTests : IDisposable
{
    // RFC 6238 appendix B: the secret is the ASCII string repeated up to the hash length.
    private static readonly byte[] Sha1Secret = Encoding.ASCII.GetBytes("12345678901234567890");
    private static readonly byte[] Sha256Secret = Encoding.ASCII.GetBytes("12345678901234567890123456789012");
    private static readonly byte[] Sha512Secret = Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234");

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tf-opt-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    private static Func<string, string?> Env(params (string Name, string Value)[] values)
        => name => values.Where(v => v.Name == name).Select(v => v.Value).FirstOrDefault();

    [Theory]
    [InlineData(59L, "46119246")]
    [InlineData(1111111109L, "68084774")]
    [InlineData(1111111111L, "67062674")]
    [InlineData(1234567890L, "91819424")]
    [InlineData(2000000000L, "90698825")]
    [InlineData(20000000000L, "77737706")]
    public void Rfc6238Vectors_Sha256(long unixTime, string expected)
    {
        var counter = TotpService.GetCounter(DateTimeOffset.FromUnixTimeSeconds(unixTime));
        Assert.Equal(expected, TotpService.ComputeCode(Sha256Secret, counter, 8, TotpAlgorithm.Sha256));
    }

    [Theory]
    [InlineData(59L, "90693936")]
    [InlineData(1111111109L, "25091201")]
    [InlineData(1111111111L, "99943326")]
    [InlineData(1234567890L, "93441116")]
    [InlineData(2000000000L, "38618901")]
    [InlineData(20000000000L, "47863826")]
    public void Rfc6238Vectors_Sha512(long unixTime, string expected)
    {
        var counter = TotpService.GetCounter(DateTimeOffset.FromUnixTimeSeconds(unixTime));
        Assert.Equal(expected, TotpService.ComputeCode(Sha512Secret, counter, 8, TotpAlgorithm.Sha512));
    }

    [Theory]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    public void Digits_ChangeTheCodeLengthAndValidationRequiresIt(int digits)
    {
        var options = new TotpOptions(digits, TotpAlgorithm.Sha256, 30);
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var code = TotpService.ComputeCode(Sha256Secret, TotpService.GetCounter(now), digits, TotpAlgorithm.Sha256);
        Assert.Equal(digits, code.Length);
        Assert.True(TotpService.TryValidate(Sha256Secret, code, now, -1, options, out _));

        var wrongLength = TotpService.ComputeCode(Sha256Secret, TotpService.GetCounter(now), digits == 8 ? 6 : digits + 1, TotpAlgorithm.Sha256);
        Assert.False(TotpService.TryValidate(Sha256Secret, wrongLength, now, -1, options, out _));
    }

    [Fact]
    public void Algorithm_MustMatch()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var counter = TotpService.GetCounter(now);
        var sha1Code = TotpService.ComputeCode(Sha1Secret, counter);
        var sha512Code = TotpService.ComputeCode(Sha1Secret, counter, 6, TotpAlgorithm.Sha512);
        Assert.NotEqual(sha1Code, sha512Code);
        Assert.True(TotpService.TryValidate(Sha1Secret, sha512Code, now, -1, new TotpOptions(6, TotpAlgorithm.Sha512, 30), out _));
        Assert.False(TotpService.TryValidate(Sha1Secret, sha512Code, now, -1, TotpOptions.Default, out _));
    }

    [Fact]
    public void Period_ChangesTheStepAndTheDriftWindow()
    {
        var options = new TotpOptions(6, TotpAlgorithm.Sha1, 60);
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_020);
        var counter = TotpService.GetCounter(now, 60);
        Assert.Equal(1_000_000_020L / 60, counter);

        Assert.True(TotpService.TryValidate(Sha1Secret, TotpService.ComputeCode(Sha1Secret, counter), now, -1, options, out var matched));
        Assert.Equal(counter, matched);
        Assert.True(TotpService.TryValidate(Sha1Secret, TotpService.ComputeCode(Sha1Secret, counter - 1), now, -1, options, out _));
        Assert.False(TotpService.TryValidate(Sha1Secret, TotpService.ComputeCode(Sha1Secret, counter + 2), now, -1, options, out _));
    }

    [Fact]
    public void InvalidOptions_NeverValidate()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var code = TotpService.ComputeCode(Sha1Secret, TotpService.GetCounter(now));
        Assert.False(TotpService.TryValidate(Sha1Secret, code, now, -1, new TotpOptions(5, TotpAlgorithm.Sha1, 30), out _));
        Assert.False(TotpService.TryValidate(Sha1Secret, code, now, -1, new TotpOptions(6, TotpAlgorithm.Sha1, 0), out _));
    }

    [Fact]
    public void OtpAuthUri_CarriesTheConfiguredParameters()
    {
        var uri = TotpService.BuildOtpAuthUri("Jellyfin", "ana", Sha1Secret, new TotpOptions(8, TotpAlgorithm.Sha512, 60));
        Assert.EndsWith("&issuer=Jellyfin&algorithm=SHA512&digits=8&period=60", uri);
    }

    [Fact]
    public void Environment_Unset_UsesDefaults()
    {
        Assert.True(TotpOptions.TryFromEnvironment(Env(), out var options, out var errors));
        Assert.Empty(errors);
        Assert.Equal(TotpOptions.Default, options);
        Assert.Equal(new TotpOptions(6, TotpAlgorithm.Sha1, 30), options);
    }

    [Fact]
    public void Environment_EmptyValues_UseDefaults()
    {
        Assert.True(TotpOptions.TryFromEnvironment(
            Env((TotpOptions.DigitsVariable, ""), (TotpOptions.AlgorithmVariable, "  "), (TotpOptions.PeriodVariable, "")),
            out var options,
            out _));
        Assert.Equal(TotpOptions.Default, options);
    }

    [Fact]
    public void Environment_ValidValues_AreParsed_CaseInsensitive()
    {
        Assert.True(TotpOptions.TryFromEnvironment(
            Env((TotpOptions.DigitsVariable, " 8 "), (TotpOptions.AlgorithmVariable, "sha256"), (TotpOptions.PeriodVariable, "60")),
            out var options,
            out var errors));
        Assert.Empty(errors);
        Assert.Equal(new TotpOptions(8, TotpAlgorithm.Sha256, 60), options);
    }

    [Theory]
    [InlineData("6", "SHA1", "15")]
    [InlineData("7", "SHA512", "300")]
    public void Environment_BoundariesAreAccepted(string digits, string algorithm, string period)
    {
        Assert.True(TotpOptions.TryFromEnvironment(
            Env((TotpOptions.DigitsVariable, digits), (TotpOptions.AlgorithmVariable, algorithm), (TotpOptions.PeriodVariable, period)),
            out _,
            out _));
    }

    [Theory]
    [InlineData(TotpOptions.DigitsVariable, "5")]
    [InlineData(TotpOptions.DigitsVariable, "9")]
    [InlineData(TotpOptions.DigitsVariable, "0")]
    [InlineData(TotpOptions.DigitsVariable, "-6")]
    [InlineData(TotpOptions.DigitsVariable, "six")]
    [InlineData(TotpOptions.DigitsVariable, "6.0")]
    [InlineData(TotpOptions.AlgorithmVariable, "MD5")]
    [InlineData(TotpOptions.AlgorithmVariable, "SHA-256")]
    [InlineData(TotpOptions.AlgorithmVariable, "SHA384")]
    [InlineData(TotpOptions.PeriodVariable, "14")]
    [InlineData(TotpOptions.PeriodVariable, "301")]
    [InlineData(TotpOptions.PeriodVariable, "0")]
    [InlineData(TotpOptions.PeriodVariable, "-30")]
    [InlineData(TotpOptions.PeriodVariable, "30s")]
    public void Environment_InvalidValue_IsAnErrorNotADefault(string variable, string value)
    {
        Assert.False(TotpOptions.TryFromEnvironment(Env((variable, value)), out _, out var errors));
        var error = Assert.Single(errors);
        Assert.Contains(variable, error);
    }

    [Fact]
    public void Environment_ReportsEveryInvalidVariable()
    {
        Assert.False(TotpOptions.TryFromEnvironment(
            Env((TotpOptions.DigitsVariable, "x"), (TotpOptions.AlgorithmVariable, "y"), (TotpOptions.PeriodVariable, "z")),
            out _,
            out var errors));
        Assert.Equal(3, errors.Count);
    }

    [Fact]
    public void Store_KeepsEachUsersOwnParameters_WhenSettingsChangeLater()
    {
        var cipher = new SeedCipher(new byte[32]);
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var oldUser = Guid.NewGuid();
        var newUser = Guid.NewGuid();
        var oldSecret = TotpService.GenerateSecret();
        var newSecret = TotpService.GenerateSecret();
        var custom = new TotpOptions(8, TotpAlgorithm.Sha512, 60);

        var store = new FileSeedStore(_dir, cipher, NullLogger.Instance);
        store.TryEnroll(oldUser, oldSecret, -1, TotpOptions.Default);
        store.TryEnroll(newUser, newSecret, -1, custom);

        var reopened = new FileSeedStore(_dir, cipher, NullLogger.Instance);
        var oldCode = TotpService.ComputeCode(oldSecret, TotpService.GetCounter(now));
        var newCode = TotpService.ComputeCode(newSecret, TotpService.GetCounter(now, 60), 8, TotpAlgorithm.Sha512);
        Assert.True(reopened.TryAcceptCode(oldUser, oldCode, now));
        Assert.True(reopened.TryAcceptCode(newUser, newCode, now));
        Assert.False(reopened.TryAcceptCode(newUser, newCode, now));
    }

    [Fact]
    public void Entry_WithoutParameters_GetsTheDefaults()
    {
        var entry = JsonSerializer.Deserialize<SeedEntry>("{\"userId\":\"" + Guid.NewGuid() + "\",\"secret\":\"JBSWY3DPEHPK3PXP\",\"enabled\":true,\"lastCounter\":-1}")!;
        Assert.Equal(TotpOptions.Default, entry.GetOptions());
    }

    [Fact]
    public void Entry_WithInvalidParameters_HasNoOptions()
    {
        Assert.Null(new SeedEntry { Digits = 12 }.GetOptions());
        Assert.Null(new SeedEntry { Algorithm = "MD5" }.GetOptions());
        Assert.Null(new SeedEntry { PeriodSeconds = 5 }.GetOptions());
    }
}
