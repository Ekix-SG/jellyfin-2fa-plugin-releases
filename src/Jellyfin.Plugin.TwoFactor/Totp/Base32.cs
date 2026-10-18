using System;
using System.Text;

namespace Jellyfin.Plugin.TwoFactor.Totp;

/// <summary>
/// RFC 4648 Base32 encoding (upper-case alphabet, no padding on output).
/// </summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>
    /// Encodes bytes as unpadded Base32.
    /// </summary>
    /// <param name="data">The bytes to encode.</param>
    /// <returns>The Base32 text.</returns>
    public static string Encode(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder((data.Length * 8 / 5) + 1);
        int buffer = 0;
        int bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }

            buffer &= (1 << bits) - 1;
        }

        if (bits > 0)
        {
            sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Decodes Base32 text. Case, spaces, dashes and '=' padding are ignored.
    /// </summary>
    /// <param name="text">The Base32 text.</param>
    /// <param name="data">The decoded bytes.</param>
    /// <returns><c>true</c> if the text was valid.</returns>
    public static bool TryDecode(string text, out byte[] data)
    {
        var result = new byte[(text.Length * 5 / 8) + 1];
        int count = 0;
        int buffer = 0;
        int bits = 0;
        foreach (var c in text)
        {
            if (c is ' ' or '-' or '=')
            {
                continue;
            }

            int value = Alphabet.IndexOf(char.ToUpperInvariant(c), StringComparison.Ordinal);
            if (value < 0)
            {
                data = Array.Empty<byte>();
                return false;
            }

            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                result[count++] = (byte)((buffer >> (bits - 8)) & 0xFF);
                bits -= 8;
            }

            buffer &= (1 << bits) - 1;
        }

        data = result.AsSpan(0, count).ToArray();
        return true;
    }
}
