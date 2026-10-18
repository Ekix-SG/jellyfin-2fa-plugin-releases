using System.Security.Cryptography;
using Jellyfin.Plugin.TwoFactor.Storage;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public class SeedCipherTests
{
    private static SeedCipher NewCipher() => new(RandomNumberGenerator.GetBytes(32));

    [Fact]
    public void RoundTrip_ReturnsTheOriginalText()
    {
        var cipher = NewCipher();
        var user = Guid.NewGuid();
        var encoded = cipher.Encrypt("ünïcode secret ✓", user);
        Assert.True(cipher.TryDecrypt(encoded, user, out var plain));
        Assert.Equal("ünïcode secret ✓", plain);
    }

    [Fact]
    public void Layout_IsVersionNonceTagCiphertext()
    {
        var raw = Convert.FromBase64String(NewCipher().Encrypt("abc", Guid.NewGuid()));
        Assert.Equal(1 + 12 + 16 + 3, raw.Length);
        Assert.Equal(1, raw[0]);
    }

    [Fact]
    public void Nonce_IsDifferentOnEveryEncryption()
    {
        var cipher = NewCipher();
        var user = Guid.NewGuid();
        var nonces = new HashSet<string>();
        var outputs = new HashSet<string>();
        for (int i = 0; i < 50; i++)
        {
            var encoded = cipher.Encrypt("same text", user);
            outputs.Add(encoded);
            nonces.Add(Convert.ToBase64String(Convert.FromBase64String(encoded).AsSpan(1, 12)));
        }

        Assert.Equal(50, nonces.Count);
        Assert.Equal(50, outputs.Count);
    }

    [Fact]
    public void WrongKey_Fails()
    {
        var user = Guid.NewGuid();
        var encoded = NewCipher().Encrypt("secret", user);
        Assert.False(NewCipher().TryDecrypt(encoded, user, out var plain));
        Assert.Equal(string.Empty, plain);
    }

    [Fact]
    public void EntryCopiedToAnotherUser_Fails()
    {
        var cipher = NewCipher();
        var encoded = cipher.Encrypt("secret", Guid.NewGuid());
        Assert.False(cipher.TryDecrypt(encoded, Guid.NewGuid(), out _));
    }

    [Theory]
    [InlineData(0, "version")]
    [InlineData(1, "nonce")]
    [InlineData(12, "nonce")]
    [InlineData(13, "tag")]
    [InlineData(28, "tag")]
    [InlineData(29, "ciphertext")]
    public void AlteringAnyByte_Fails(int index, string part)
    {
        var cipher = NewCipher();
        var user = Guid.NewGuid();
        var raw = Convert.FromBase64String(cipher.Encrypt("secret text", user));
        raw[index] ^= 0x01;
        Assert.False(cipher.TryDecrypt(Convert.ToBase64String(raw), user, out _), part);
    }

    [Fact]
    public void LastByteOfCiphertext_IsAuthenticated()
    {
        var cipher = NewCipher();
        var user = Guid.NewGuid();
        var raw = Convert.FromBase64String(cipher.Encrypt("secret text", user));
        raw[^1] ^= 0x80;
        Assert.False(cipher.TryDecrypt(Convert.ToBase64String(raw), user, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not base64!!")]
    [InlineData("AAAA")]
    public void MalformedInput_FailsWithoutThrowing(string input)
    {
        Assert.False(NewCipher().TryDecrypt(input, Guid.NewGuid(), out _));
    }

    [Fact]
    public void TruncatedData_Fails()
    {
        var cipher = NewCipher();
        var user = Guid.NewGuid();
        var raw = Convert.FromBase64String(cipher.Encrypt("secret text", user));
        Assert.False(cipher.TryDecrypt(Convert.ToBase64String(raw[..^1]), user, out _));
        Assert.False(cipher.TryDecrypt(Convert.ToBase64String(raw[..20]), user, out _));
    }

    [Fact]
    public void Key_MustBeExactly32Bytes()
    {
        foreach (var length in new[] { 0, 1, 16, 24, 31, 33, 64 })
        {
            Assert.Throws<ArgumentException>(() => new SeedCipher(new byte[length]));
        }

        _ = new SeedCipher(new byte[32]);
    }

    [Fact]
    public void KeyParsing_AcceptsOnly32BytesOfStandardBase64()
    {
        var good = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        Assert.Equal(44, good.Length);
        Assert.True(SeedCipher.TryCreateFromBase64(good, out var cipher));
        Assert.NotNull(cipher);
        Assert.True(SeedCipher.TryCreateFromBase64("  " + good + "\n", out _));

        Assert.False(SeedCipher.TryCreateFromBase64(null, out _));
        Assert.False(SeedCipher.TryCreateFromBase64(string.Empty, out _));
        Assert.False(SeedCipher.TryCreateFromBase64("   ", out _));
        Assert.False(SeedCipher.TryCreateFromBase64(good.TrimEnd('='), out _));
        Assert.False(SeedCipher.TryCreateFromBase64(good[..^2] + "!=", out _));
        Assert.False(SeedCipher.TryCreateFromBase64("not a key", out _));

        foreach (var length in new[] { 1, 16, 24, 31, 33, 48, 64 })
        {
            var text = Convert.ToBase64String(RandomNumberGenerator.GetBytes(length));
            Assert.False(SeedCipher.TryCreateFromBase64(text, out _), $"{length} bytes");
        }
    }

    [Fact]
    public void ParsedKey_WorksLikeTheOriginalBytes()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var user = Guid.NewGuid();
        var encoded = new SeedCipher(bytes).Encrypt("x", user);
        Assert.True(SeedCipher.TryCreateFromBase64(Convert.ToBase64String(bytes), out var parsed));
        Assert.True(parsed!.TryDecrypt(encoded, user, out var plain));
        Assert.Equal("x", plain);
    }
}
