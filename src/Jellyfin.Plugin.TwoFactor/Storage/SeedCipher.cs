using System;
using System.Security.Cryptography;
using System.Text;

namespace Jellyfin.Plugin.TwoFactor.Storage;

/// <summary>
/// AES-256-GCM encryption of seed entries.
/// Binary layout, then Base64: format version (1 byte) | nonce (12 bytes, new for every encryption)
/// | authentication tag (16 bytes) | ciphertext. The user id is the associated data (AAD), so an
/// entry copied to another user, or altered in any byte, fails to decrypt.
/// </summary>
public sealed class SeedCipher
{
    /// <summary>The only accepted key length in bytes (AES-256).</summary>
    public const int KeyLength = 32;

    /// <summary>Name of the environment variable holding the key.</summary>
    public const string KeyEnvironmentVariable = "TWOFACTOR_KEY";

    private const byte FormatVersion = 1;
    private const int NonceLength = 12;
    private const int TagLength = 16;

    private readonly byte[] _key;

    /// <summary>
    /// Initializes a new instance of the <see cref="SeedCipher"/> class.
    /// </summary>
    /// <param name="key">The key; exactly <see cref="KeyLength"/> bytes.</param>
    public SeedCipher(byte[] key)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException($"The key must be exactly {KeyLength} bytes.", nameof(key));
        }

        _key = (byte[])key.Clone();
    }

    /// <summary>
    /// Parses a key from its Base64 text. Surrounding whitespace is ignored.
    /// </summary>
    /// <param name="text">The Base64 text, usually the value of <see cref="KeyEnvironmentVariable"/>.</param>
    /// <param name="cipher">The cipher, if the key is valid.</param>
    /// <returns><c>true</c> if the text is standard Base64 that decodes to exactly 32 bytes.</returns>
    public static bool TryCreateFromBase64(string? text, out SeedCipher? cipher)
    {
        cipher = null;
        var trimmed = text?.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            return false;
        }

        // Upper bound on the text size before decoding: 32 bytes is 44 Base64 characters.
        if (trimmed.Length != 44)
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[KeyLength + 3];
        if (!Convert.TryFromBase64String(trimmed, buffer, out var written) || written != KeyLength)
        {
            return false;
        }

        cipher = new SeedCipher(buffer[..KeyLength].ToArray());
        CryptographicOperations.ZeroMemory(buffer);
        return true;
    }

    /// <summary>
    /// Encrypts a text for a user.
    /// </summary>
    /// <param name="plaintext">The text.</param>
    /// <param name="userId">The owner, bound as associated data.</param>
    /// <returns>The Base64 text.</returns>
    public string Encrypt(string plaintext, Guid userId)
    {
        var data = Encoding.UTF8.GetBytes(plaintext);
        var result = new byte[1 + NonceLength + TagLength + data.Length];
        result[0] = FormatVersion;
        var nonce = result.AsSpan(1, NonceLength);
        var tag = result.AsSpan(1 + NonceLength, TagLength);
        var cipherText = result.AsSpan(1 + NonceLength + TagLength);
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(_key, TagLength);
        aes.Encrypt(nonce, data, cipherText, tag, userId.ToByteArray());
        CryptographicOperations.ZeroMemory(data);
        return Convert.ToBase64String(result);
    }

    /// <summary>
    /// Decrypts and authenticates a text for a user.
    /// </summary>
    /// <param name="encoded">The Base64 text.</param>
    /// <param name="userId">The owner, checked as associated data.</param>
    /// <param name="plaintext">The text, if authentic.</param>
    /// <returns><c>false</c> on any problem: wrong key, wrong user, altered or malformed data, unknown version.</returns>
    public bool TryDecrypt(string encoded, Guid userId, out string plaintext)
    {
        plaintext = string.Empty;
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(encoded);
        }
        catch (FormatException)
        {
            return false;
        }

        if (raw.Length < 1 + NonceLength + TagLength || raw[0] != FormatVersion)
        {
            return false;
        }

        var nonce = raw.AsSpan(1, NonceLength);
        var tag = raw.AsSpan(1 + NonceLength, TagLength);
        var cipherText = raw.AsSpan(1 + NonceLength + TagLength);
        var data = new byte[cipherText.Length];
        try
        {
            using var aes = new AesGcm(_key, TagLength);
            aes.Decrypt(nonce, cipherText, tag, data, userId.ToByteArray());
            plaintext = Encoding.UTF8.GetString(data);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }
}
