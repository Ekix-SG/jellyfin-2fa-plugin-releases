using Jellyfin.Plugin.TwoFactor.Totp;

namespace Jellyfin.Plugin.TwoFactor.Tests;

/// <summary>
/// Google Authenticator "Key URI Format":
/// otpauth://totp/ISSUER:ACCOUNT?secret=BASE32&amp;issuer=ISSUER&amp;algorithm=SHA1&amp;digits=6&amp;period=30
/// </summary>
public class OtpAuthUriTests
{
    private static byte[] FakeSecret()
    {
        Assert.True(Base32.TryDecode("JBSWY3DPEHPK3PXP", out var secret));
        return secret;
    }

    [Fact]
    public void ExampleUri_MatchesTheKeyUriFormat()
    {
        Assert.Equal(
            "otpauth://totp/Jellyfin:ana?secret=JBSWY3DPEHPK3PXP&issuer=Jellyfin&algorithm=SHA1&digits=6&period=30",
            TotpService.BuildOtpAuthUri("Jellyfin", "ana", FakeSecret()));
    }

    [Fact]
    public void Secret_IsUppercaseBase32WithoutPadding()
    {
        // 20 random bytes encode to exactly 32 characters, so no '=' would be needed in any case;
        // 10 bytes also encode without padding. Check an input that WOULD need padding (11 bytes).
        var uri = TotpService.BuildOtpAuthUri("Jellyfin", "ana", new byte[11]);
        var secret = uri.Split("secret=")[1].Split('&')[0];
        Assert.DoesNotContain('=', secret);
        Assert.Equal(secret.ToUpperInvariant(), secret);
        Assert.Matches("^[A-Z2-7]+$", secret);
    }

    [Fact]
    public void IssuerAndAccount_WithSpacesAndAt_UsePercentEncodingNotPlus()
    {
        var uri = TotpService.BuildOtpAuthUri("Mi Servidor", "ana lópez@casa.es", FakeSecret());
        Assert.Contains("/Mi%20Servidor:ana%20l%C3%B3pez%40casa.es?", uri);
        Assert.Contains("issuer=Mi%20Servidor&", uri);
        Assert.DoesNotContain('+', uri);
        Assert.DoesNotContain(' ', uri);
    }

    [Fact]
    public void ColonsInsideIssuerOrAccount_AreEncoded_SoOnlyTheSeparatorIsLiteral()
    {
        var uri = TotpService.BuildOtpAuthUri("A:B", "c:d", FakeSecret());
        Assert.Contains("/A%3AB:c%3Ad?", uri);
    }

    [Theory]
    [InlineData("Jellyfin", "ana")]
    [InlineData("Mi Servidor", "ana@casa.es")]
    [InlineData("A&B=C", "x/y")]
    public void Issuer_IsIdenticalInLabelAndParameter(string issuer, string account)
    {
        var uri = TotpService.BuildOtpAuthUri(issuer, account, FakeSecret());
        var escaped = Uri.EscapeDataString(issuer);
        Assert.StartsWith("otpauth://totp/" + escaped + ":", uri);
        Assert.Contains("&issuer=" + escaped + "&", uri);
    }

    [Fact]
    public void Parameters_AreConsistentWithTotpServiceConstants()
    {
        var uri = TotpService.BuildOtpAuthUri("Jellyfin", "ana", FakeSecret());
        Assert.Contains("algorithm=SHA1", uri);
        Assert.Contains($"digits={TotpService.Digits}", uri);
        Assert.Contains($"period={TotpService.StepSeconds}", uri);
        Assert.Equal(6, TotpService.Digits);
        Assert.Equal(30, TotpService.StepSeconds);
    }

    [Fact]
    public void ParsedUri_RoundTripsTheValues()
    {
        var uri = new Uri(TotpService.BuildOtpAuthUri("Mi Servidor", "ana@casa.es", FakeSecret()));
        Assert.Equal("otpauth", uri.Scheme);
        Assert.Equal("totp", uri.Host);
        Assert.Equal("/Mi Servidor:ana@casa.es", Uri.UnescapeDataString(uri.AbsolutePath));
    }
}
