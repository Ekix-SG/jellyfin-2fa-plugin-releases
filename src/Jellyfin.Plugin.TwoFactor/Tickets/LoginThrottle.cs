using System;
using System.Collections.Generic;
using System.Linq;

namespace Jellyfin.Plugin.TwoFactor.Tickets;

/// <summary>
/// In-memory temporary block by client IP and by user name, on top of the per-ticket limit of <see cref="TicketStore"/>
/// (which an attacker gets around by asking for new tickets). Failures older than <see cref="Window"/> are forgotten;
/// once a key has <see cref="MaxFailuresPerIp"/> / <see cref="MaxFailuresPerUser"/> failures inside the window it is
/// blocked until its oldest counted failure leaves the window. A blocked request gets the same uniform error as any other
/// failure, so nothing tells an attacker apart a block from a wrong password.
/// The per-user limit is deliberately higher than the per-IP one, and a successful login clears the user's counter,
/// so that someone typing the user name of a victim cannot easily lock them out of their own account.
/// </summary>
public class LoginThrottle
{
    /// <summary>Failures from one IP inside <see cref="Window"/> that block it.</summary>
    public const int MaxFailuresPerIp = 15;

    /// <summary>Failures for one user name inside <see cref="Window"/> that block it.</summary>
    public const int MaxFailuresPerUser = 30;

    private const int MaxTrackedKeys = 10_000;

    private readonly object _lock = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _byIp = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Queue<DateTimeOffset>> _byUser = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;

    /// <summary>
    /// Initializes a new instance of the <see cref="LoginThrottle"/> class.
    /// </summary>
    /// <param name="time">The clock.</param>
    public LoginThrottle(TimeProvider time)
    {
        _time = time;
    }

    /// <summary>
    /// Gets the length of the sliding window.
    /// </summary>
    public static TimeSpan Window { get; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Gets a value indicating whether a request from this IP, or for this user name, is currently blocked.
    /// </summary>
    /// <param name="ip">The client IP.</param>
    /// <param name="username">The user name, if known.</param>
    /// <returns><c>true</c> if blocked.</returns>
    public bool IsBlocked(string ip, string? username)
    {
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            return Count(_byIp, ip, now) >= MaxFailuresPerIp
                || (!string.IsNullOrEmpty(username) && Count(_byUser, Normalize(username), now) >= MaxFailuresPerUser);
        }
    }

    /// <summary>
    /// Records a failed attempt.
    /// </summary>
    /// <param name="ip">The client IP.</param>
    /// <param name="username">The user name, if known.</param>
    public void RegisterFailure(string ip, string? username)
    {
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            Add(_byIp, ip, now);
            if (!string.IsNullOrEmpty(username))
            {
                Add(_byUser, Normalize(username), now);
            }
        }
    }

    /// <summary>
    /// Clears the counter of a user after a complete, successful login.
    /// </summary>
    /// <param name="username">The user name.</param>
    public void RegisterSuccess(string username)
    {
        lock (_lock)
        {
            _byUser.Remove(Normalize(username));
        }
    }

    private static string Normalize(string username) => username.Trim().ToUpperInvariant();

    private static int Count(Dictionary<string, Queue<DateTimeOffset>> map, string key, DateTimeOffset now)
    {
        if (!map.TryGetValue(key, out var queue))
        {
            return 0;
        }

        Trim(queue, now);
        if (queue.Count == 0)
        {
            map.Remove(key);
        }

        return queue.Count;
    }

    private static void Add(Dictionary<string, Queue<DateTimeOffset>> map, string key, DateTimeOffset now)
    {
        if (!map.TryGetValue(key, out var queue))
        {
            if (map.Count >= MaxTrackedKeys)
            {
                foreach (var stale in map.Where(pair => Trim(pair.Value, now) == 0).Select(pair => pair.Key).ToList())
                {
                    map.Remove(stale);
                }

                if (map.Count >= MaxTrackedKeys)
                {
                    // Still full of live keys: stop tracking new ones rather than grow without bound.
                    return;
                }
            }

            queue = new Queue<DateTimeOffset>();
            map[key] = queue;
        }

        Trim(queue, now);
        queue.Enqueue(now);
    }

    private static int Trim(Queue<DateTimeOffset> queue, DateTimeOffset now)
    {
        while (queue.Count > 0 && queue.Peek() + Window <= now)
        {
            queue.Dequeue();
        }

        return queue.Count;
    }
}
