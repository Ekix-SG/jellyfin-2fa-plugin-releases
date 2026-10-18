using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactor.Storage;

/// <summary>
/// Invitation store backed by <c>invites.json</c>, next to <c>seeds.json</c> and encrypted the same way
/// (<see cref="SeedCipher"/>, user id as associated data). Only a salted SHA-256 hash of each code is kept,
/// together with the user id, the expiry and the failure counter. The plain code is never stored or logged.
/// Without a cipher the store is unavailable and the file is neither read nor written.
/// </summary>
public class FileInviteStore : IInviteStore
{
    /// <summary>Maximum wrong codes per invitation.</summary>
    public const int MaxFailedAttempts = 5;

    /// <summary>Length of a code.</summary>
    public const int CodeLength = 10;

    // No 0, O, 1, I or L. 31 symbols ^ 10 characters is about 49 bits.
    private const string Alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

    private const int CurrentFileVersion = 1;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly object _lock = new();
    private readonly string _path;
    private readonly SeedCipher? _cipher;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly Dictionary<Guid, InviteEntry> _entries = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="FileInviteStore"/> class.
    /// </summary>
    /// <param name="directory">The directory holding <c>invites.json</c>; created if missing.</param>
    /// <param name="cipher">The cipher, or <c>null</c> if no valid key is configured.</param>
    /// <param name="time">The clock.</param>
    /// <param name="logger">The logger.</param>
    public FileInviteStore(string directory, SeedCipher? cipher, TimeProvider time, ILogger logger)
    {
        _path = Path.Combine(directory, "invites.json");
        _cipher = cipher;
        _time = time;
        _logger = logger;
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory);
        }
        else
        {
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        if (_cipher is not null)
        {
            Load();
        }
    }

    /// <inheritdoc />
    public bool IsAvailable => _cipher is not null;

    /// <inheritdoc />
    public InviteIssued Create(Guid userId, TimeSpan ttl)
    {
        EnsureAvailable();
        var code = GenerateCode();
        var salt = RandomNumberGenerator.GetBytes(16);
        var expiresAt = _time.GetUtcNow() + ttl;
        var entry = new InviteEntry
        {
            InviteId = Guid.NewGuid(),
            UserId = userId,
            Salt = Convert.ToBase64String(salt),
            Hash = Convert.ToBase64String(ComputeHash(salt, userId, code)),
            ExpiresAt = expiresAt
        };

        lock (_lock)
        {
            _entries.TryGetValue(userId, out var previous);
            _entries[userId] = entry;
            try
            {
                Save();
            }
            catch
            {
                if (previous is null)
                {
                    _entries.Remove(userId);
                }
                else
                {
                    _entries[userId] = previous;
                }

                throw;
            }
        }

        return new InviteIssued(entry.InviteId, code, expiresAt);
    }

    /// <inheritdoc />
    public Guid? TryValidate(Guid userId, string? code)
    {
        EnsureAvailable();
        var normalized = Normalize(code);
        lock (_lock)
        {
            if (!TryGetLive(userId, out var entry) || normalized is null)
            {
                return null;
            }

            var salt = Convert.FromBase64String(entry.Salt);
            var expected = Convert.FromBase64String(entry.Hash);
            return CryptographicOperations.FixedTimeEquals(ComputeHash(salt, userId, normalized), expected) ? entry.InviteId : null;
        }
    }

    /// <inheritdoc />
    public bool IsActive(Guid inviteId)
    {
        EnsureAvailable();
        lock (_lock)
        {
            var entry = _entries.Values.FirstOrDefault(e => e.InviteId == inviteId);
            return entry is not null && TryGetLive(entry.UserId, out _);
        }
    }

    /// <inheritdoc />
    public bool Consume(Guid inviteId)
    {
        EnsureAvailable();
        lock (_lock)
        {
            var entry = _entries.Values.FirstOrDefault(e => e.InviteId == inviteId);
            if (entry is null || !TryGetLive(entry.UserId, out _))
            {
                return false;
            }

            return RemoveEntry(entry);
        }
    }

    /// <inheritdoc />
    public bool Revoke(Guid userId)
    {
        EnsureAvailable();
        lock (_lock)
        {
            return _entries.TryGetValue(userId, out var entry) && RemoveEntry(entry);
        }
    }

    /// <inheritdoc />
    public void RegisterFailure(Guid userId)
    {
        EnsureAvailable();
        lock (_lock)
        {
            if (!TryGetLive(userId, out var entry))
            {
                return;
            }

            if (entry.Failures + 1 >= MaxFailedAttempts)
            {
                RemoveEntry(entry);
                _logger.LogWarning("TwoFactor: the invitation code of user {UserId} was invalidated after too many wrong codes.", userId);
                return;
            }

            entry.Failures++;
            try
            {
                Save();
            }
            catch
            {
                entry.Failures--;
                throw;
            }
        }
    }

    /// <inheritdoc />
    public InviteInfo? GetActive(Guid userId)
    {
        EnsureAvailable();
        lock (_lock)
        {
            return TryGetLive(userId, out var entry) ? new InviteInfo(entry.InviteId, entry.ExpiresAt) : null;
        }
    }

    private static string GenerateCode()
    {
        var chars = new char[CodeLength];
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        }

        return new string(chars);
    }

    // Case, spaces and hyphens are ignored so that "abcde-fghjk" works; anything else that is not a code gives null.
    private static string? Normalize(string? code)
    {
        if (string.IsNullOrEmpty(code) || code.Length > 64)
        {
            return null;
        }

        var text = new string(code.Where(c => c is not (' ' or '-')).ToArray()).ToUpperInvariant();
        return text.Length == CodeLength && text.All(c => Alphabet.Contains(c)) ? text : null;
    }

    private static byte[] ComputeHash(byte[] salt, Guid userId, string code)
    {
        var data = salt.Concat(userId.ToByteArray()).Concat(Encoding.UTF8.GetBytes(code)).ToArray();
        return SHA256.HashData(data);
    }

    // Looks the user's entry up; an expired one is dropped on the way (best effort: a failed save is retried at the next write).
    private bool TryGetLive(Guid userId, out InviteEntry entry)
    {
        if (_entries.TryGetValue(userId, out entry!))
        {
            if (entry.ExpiresAt > _time.GetUtcNow())
            {
                return true;
            }

            _entries.Remove(userId);
            try
            {
                Save();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogWarning("TwoFactor: could not remove an expired invitation from invites.json ({Reason}).", ex.GetType().Name);
            }
        }

        return false;
    }

    private bool RemoveEntry(InviteEntry entry)
    {
        _entries.Remove(entry.UserId);
        try
        {
            Save();
        }
        catch
        {
            _entries[entry.UserId] = entry;
            throw;
        }

        return true;
    }

    private void EnsureAvailable()
    {
        if (_cipher is null)
        {
            throw new InvalidOperationException("No valid encryption key is configured.");
        }
    }

    private void Load()
    {
        if (!File.Exists(_path))
        {
            return;
        }

        var file = JsonSerializer.Deserialize<InviteFile>(File.ReadAllText(_path));
        var dropped = 0;
        foreach (var item in file?.Invites ?? new List<EncryptedItem>())
        {
            if (_cipher!.TryDecrypt(item.Data, item.UserId, out var json)
                && JsonSerializer.Deserialize<InviteEntry>(json) is { } entry
                && entry.UserId == item.UserId)
            {
                _entries[item.UserId] = entry;
            }
            else
            {
                dropped++;
            }
        }

        if (dropped > 0)
        {
            // Invitations are disposable: an unreadable one is simply lost and a new one can be generated.
            _logger.LogWarning("TwoFactor: {Count} invitation(s) in invites.json could not be decrypted and were ignored.", dropped);
        }
    }

    private void Save()
    {
        var file = new InviteFile { Version = CurrentFileVersion };
        foreach (var entry in _entries.Values)
        {
            file.Invites.Add(new EncryptedItem
            {
                UserId = entry.UserId,
                Data = _cipher!.Encrypt(JsonSerializer.Serialize(entry), entry.UserId)
            });
        }

        var temp = _path + ".tmp";
        File.Delete(temp);

        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        using (var stream = new FileStream(temp, options))
        {
            JsonSerializer.Serialize(stream, file, JsonOptions);
            stream.Flush(true);
        }

        File.Move(temp, _path, overwrite: true);
    }

    private sealed class InviteEntry
    {
        [JsonPropertyName("inviteId")]
        public Guid InviteId { get; set; }

        [JsonPropertyName("userId")]
        public Guid UserId { get; set; }

        [JsonPropertyName("salt")]
        public string Salt { get; set; } = string.Empty;

        [JsonPropertyName("hash")]
        public string Hash { get; set; } = string.Empty;

        [JsonPropertyName("expiresAt")]
        public DateTimeOffset ExpiresAt { get; set; }

        [JsonPropertyName("failures")]
        public int Failures { get; set; }
    }

    private sealed class InviteFile
    {
        [JsonPropertyName("version")]
        public int Version { get; set; } = CurrentFileVersion;

        [JsonPropertyName("invites")]
        public List<EncryptedItem> Invites { get; set; } = new();
    }

    private sealed class EncryptedItem
    {
        [JsonPropertyName("userId")]
        public Guid UserId { get; set; }

        [JsonPropertyName("data")]
        public string Data { get; set; } = string.Empty;
    }
}
