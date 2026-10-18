using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using Jellyfin.Plugin.TwoFactor.Totp;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactor.Storage;

/// <summary>
/// Seed store backed by a JSON file whose entries are encrypted with <see cref="SeedCipher"/>
/// (AES-256-GCM, user id as associated data). The whole entry (secret, enabled flag and last
/// counter) is encrypted, so none of it can be read or altered without the key.
/// Without a cipher the store is unavailable: it neither reads nor writes the file, and an existing
/// file is left untouched. Secrets, codes and keys are never logged.
/// Writes go to a temporary file in the same directory which then replaces the real one.
/// </summary>
public class FileSeedStore : ISeedStore
{
    private const int CurrentFileVersion = 2;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly object _lock = new();
    private readonly string _path;
    private readonly SeedCipher? _cipher;
    private readonly ILogger _logger;
    private readonly Dictionary<Guid, SeedEntry> _entries = new();

    // Entries that could not be decrypted (wrong key or tampering). They are kept as they are so that
    // a later start with the right key can read them, and they block enrollment for that user.
    private readonly Dictionary<Guid, string> _undecryptable = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="FileSeedStore"/> class.
    /// </summary>
    /// <param name="directory">The directory holding <c>seeds.json</c>; created if missing.</param>
    /// <param name="cipher">The cipher, or <c>null</c> if no valid key is configured.</param>
    /// <param name="logger">The logger.</param>
    public FileSeedStore(string directory, SeedCipher? cipher, ILogger logger)
    {
        _path = Path.Combine(directory, "seeds.json");
        _cipher = cipher;
        _logger = logger;
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory);
        }
        else
        {
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        if (_cipher is null)
        {
            if (File.Exists(_path))
            {
                _logger.LogWarning(
                    "TwoFactor: seeds.json exists but no valid {Variable} is configured. It was not read or modified.",
                    SeedCipher.KeyEnvironmentVariable);
            }

            return;
        }

        Load();
    }

    /// <inheritdoc />
    public bool IsAvailable => _cipher is not null;

    /// <inheritdoc />
    public bool IsEnabled(Guid userId)
    {
        EnsureAvailable();
        lock (_lock)
        {
            return _undecryptable.ContainsKey(userId)
                || (_entries.TryGetValue(userId, out var entry) && entry.Enabled);
        }
    }

    /// <inheritdoc />
    public bool TryEnroll(Guid userId, byte[] secret, long acceptedCounter, TotpOptions options)
    {
        EnsureAvailable();
        lock (_lock)
        {
            if (_undecryptable.ContainsKey(userId) || (_entries.TryGetValue(userId, out var existing) && existing.Enabled))
            {
                return false;
            }

            _entries.TryGetValue(userId, out var previous);
            _entries[userId] = CreateEntry(userId, secret, acceptedCounter, options);

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

            return true;
        }
    }

    /// <inheritdoc />
    public bool TryReplace(Guid userId, byte[] secret, long acceptedCounter, TotpOptions options)
    {
        EnsureAvailable();
        lock (_lock)
        {
            if (_undecryptable.ContainsKey(userId) || !_entries.TryGetValue(userId, out var previous) || !previous.Enabled)
            {
                return false;
            }

            _entries[userId] = CreateEntry(userId, secret, acceptedCounter, options);
            try
            {
                Save();
            }
            catch
            {
                _entries[userId] = previous;
                throw;
            }

            return true;
        }
    }

    /// <inheritdoc />
    public bool Remove(Guid userId)
    {
        EnsureAvailable();
        lock (_lock)
        {
            var hadEntry = _entries.TryGetValue(userId, out var entry);
            var hadUndecryptable = _undecryptable.TryGetValue(userId, out var data);
            if (!hadEntry && !hadUndecryptable)
            {
                return false;
            }

            _entries.Remove(userId);
            _undecryptable.Remove(userId);
            try
            {
                Save();
            }
            catch
            {
                if (hadEntry)
                {
                    _entries[userId] = entry!;
                }

                if (hadUndecryptable)
                {
                    _undecryptable[userId] = data!;
                }

                throw;
            }

            return true;
        }
    }

    /// <inheritdoc />
    public bool TryAcceptCode(Guid userId, string? code, DateTimeOffset now)
    {
        EnsureAvailable();
        lock (_lock)
        {
            if (!_entries.TryGetValue(userId, out var entry) || !entry.Enabled)
            {
                return false;
            }

            if (!Base32.TryDecode(entry.Secret, out var secret))
            {
                return false;
            }

            var options = entry.GetOptions();
            if (options is null || !TotpService.TryValidate(secret, code, now, entry.LastCounter, options, out var counter))
            {
                return false;
            }

            var previous = entry.LastCounter;
            entry.LastCounter = counter;
            try
            {
                Save();
            }
            catch
            {
                // If the counter cannot be persisted, refuse the code rather than risk a replay after a restart.
                entry.LastCounter = previous;
                throw;
            }

            return true;
        }
    }

    private static SeedEntry CreateEntry(Guid userId, byte[] secret, long acceptedCounter, TotpOptions options) => new()
    {
        UserId = userId,
        Secret = Base32.Encode(secret),
        Enabled = true,
        Digits = options.Digits,
        Algorithm = options.AlgorithmName,
        PeriodSeconds = options.PeriodSeconds,
        LastCounter = acceptedCounter
    };

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

        var text = File.ReadAllText(_path);
        var header = JsonSerializer.Deserialize<VersionHeader>(text);
        if (header is null)
        {
            return;
        }

        if (header.Version < CurrentFileVersion)
        {
            // Plain-text file written by an earlier build: read it and rewrite it encrypted, replacing the original.
            var legacy = JsonSerializer.Deserialize<LegacyFile>(text);
            foreach (var entry in legacy?.Users ?? new List<SeedEntry>())
            {
                _entries[entry.UserId] = entry;
            }

            Save();
            _logger.LogInformation("TwoFactor: migrated {Count} seed(s) from plain text to an encrypted seeds.json.", _entries.Count);
            return;
        }

        var file = JsonSerializer.Deserialize<SeedFile>(text) ?? new SeedFile();
        foreach (var item in file.Users)
        {
            if (_cipher!.TryDecrypt(item.Data, item.UserId, out var json)
                && JsonSerializer.Deserialize<SeedEntry>(json) is { } entry
                && entry.UserId == item.UserId)
            {
                _entries[item.UserId] = entry;
            }
            else
            {
                _undecryptable[item.UserId] = item.Data;
            }
        }

        if (_undecryptable.Count > 0)
        {
            _logger.LogWarning(
                "TwoFactor: {Count} stored seed(s) could not be decrypted (wrong {Variable} or modified data). Those users cannot log in or enroll until the right key is restored or seeds.json is deleted.",
                _undecryptable.Count,
                SeedCipher.KeyEnvironmentVariable);
        }
    }

    private void Save()
    {
        var file = new SeedFile { Version = CurrentFileVersion };
        foreach (var entry in _entries.Values)
        {
            file.Users.Add(new EncryptedItem
            {
                UserId = entry.UserId,
                Data = _cipher!.Encrypt(JsonSerializer.Serialize(entry), entry.UserId)
            });
        }

        foreach (var pair in _undecryptable)
        {
            file.Users.Add(new EncryptedItem { UserId = pair.Key, Data = pair.Value });
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

    private sealed class VersionHeader
    {
        // A file without "version" is the plain-text format of the first build.
        [JsonPropertyName("version")]
        public int Version { get; set; } = 1;
    }

    private sealed class LegacyFile
    {
        [JsonPropertyName("users")]
        public List<SeedEntry> Users { get; set; } = new();
    }

    private sealed class SeedFile
    {
        [JsonPropertyName("version")]
        public int Version { get; set; } = CurrentFileVersion;

        [JsonPropertyName("users")]
        public List<EncryptedItem> Users { get; set; } = new();
    }

    private sealed class EncryptedItem
    {
        [JsonPropertyName("userId")]
        public Guid UserId { get; set; }

        [JsonPropertyName("data")]
        public string Data { get; set; } = string.Empty;
    }
}
