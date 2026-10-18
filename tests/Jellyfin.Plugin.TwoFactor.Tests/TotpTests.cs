using System.Text;
using Jellyfin.Plugin.TwoFactor.Totp;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public class TotpTests
{
    // RFC 6238 appendix B, SHA-1 secret: ASCII "12345678901234567890".
    private static readonly byte[] RfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");

    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void Rfc6238Vectors_Sha1_EightDigits(long unixTime, string expected)
    {
        var counter = TotpService.GetCounter(DateTimeOffset.FromUnixTimeSeconds(unixTime));
        Assert.Equal(expected, TotpService.ComputeCode(RfcSecret, counter, 8));
    }

    [Fact]
    public void SixDigitCode_IsTheLastSixDigitsOfTheRfcVector()
    {
        var counter = TotpService.GetCounter(DateTimeOffset.FromUnixTimeSeconds(59));
        Assert.Equal("287082", TotpService.ComputeCode(RfcSecret, counter));
    }

    [Fact]
    public void GenerateSecret_Is20RandomBytes()
    {
        var a = TotpService.GenerateSecret();
        var b = TotpService.GenerateSecret();
        Assert.Equal(20, a.Length);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Validate_AcceptsCurrentStep()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var code = TotpService.ComputeCode(RfcSecret, TotpService.GetCounter(now));
        Assert.True(TotpService.TryValidate(RfcSecret, code, now, -1, out var matched));
        Assert.Equal(TotpService.GetCounter(now), matched);
    }

    [Fact]
    public void Validate_IgnoresSpaces()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var code = TotpService.ComputeCode(RfcSecret, TotpService.GetCounter(now));
        Assert.True(TotpService.TryValidate(RfcSecret, code[..3] + " " + code[3..], now, -1, out _));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void Validate_AcceptsOneStepOfDrift(int steps)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var code = TotpService.ComputeCode(RfcSecret, TotpService.GetCounter(now) + steps);
        Assert.True(TotpService.TryValidate(RfcSecret, code, now, -1, out _));
    }

    [Theory]
    [InlineData(-2)]
    [InlineData(2)]
    [InlineData(10)]
    public void Validate_RejectsTwoOrMoreStepsOfDrift(int steps)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var code = TotpService.ComputeCode(RfcSecret, TotpService.GetCounter(now) + steps);
        Assert.False(TotpService.TryValidate(RfcSecret, code, now, -1, out _));
    }

    [Fact]
    public void Validate_RejectsReplayOfSameCounter()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var counter = TotpService.GetCounter(now);
        var code = TotpService.ComputeCode(RfcSecret, counter);
        Assert.False(TotpService.TryValidate(RfcSecret, code, now, counter, out _));
    }

    [Fact]
    public void Validate_RejectsEarlierCounterThanLastAccepted()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var counter = TotpService.GetCounter(now);
        var older = TotpService.ComputeCode(RfcSecret, counter - 1);
        Assert.False(TotpService.TryValidate(RfcSecret, older, now, counter, out _));
    }

    [Fact]
    public void Validate_AcceptsLaterCounterAfterLastAccepted()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        var counter = TotpService.GetCounter(now);
        var next = TotpService.ComputeCode(RfcSecret, counter + 1);
        Assert.True(TotpService.TryValidate(RfcSecret, next, now, counter, out var matched));
        Assert.Equal(counter + 1, matched);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("abcdef")]
    public void Validate_RejectsMalformedCodes(string? code)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
        Assert.False(TotpService.TryValidate(RfcSecret, code, now, -1, out _));
    }

    [Fact]
    public void OtpAuthUri_ContainsEscapedLabelAndParameters()
    {
        var uri = TotpService.BuildOtpAuthUri("My Server", "ana@casa", RfcSecret);
        Assert.StartsWith("otpauth://totp/My%20Server:ana%40casa?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", uri);
        Assert.Contains("issuer=My%20Server", uri);
        Assert.Contains("algorithm=SHA1&digits=6&period=30", uri);
    }

    [Fact]
    public void Base32_RoundTripsAndMatchesRfc4648Vectors()
    {
        Assert.Equal("MZXW6YTBOI", Base32.Encode("foobar"u8));
        Assert.Equal("MZXW6", Base32.Encode("foo"u8));
        Assert.Equal(string.Empty, Base32.Encode(ReadOnlySpan<byte>.Empty));

        Assert.True(Base32.TryDecode("mzxw 6ytb-oi==", out var decoded));
        Assert.Equal("foobar", Encoding.ASCII.GetString(decoded));

        var random = TotpService.GenerateSecret();
        Assert.True(Base32.TryDecode(Base32.Encode(random), out var back));
        Assert.Equal(random, back);
    }

    [Fact]
    public void Base32_RejectsInvalidCharacters()
    {
        Assert.False(Base32.TryDecode("MZXW1", out _));
    }
}
