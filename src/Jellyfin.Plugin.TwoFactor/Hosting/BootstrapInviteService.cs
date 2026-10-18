using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactor.Storage;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactor.Hosting;

/// <summary>
/// Solves the first-administrator problem: nobody can open the administration page before having an authenticator.
/// At every start-up, if no administrator has an authenticator, it generates a new code (replacing any earlier one, so the server never stays locked out) for
/// each administrator without one and writes it to the server log (a warning, once per start). The log is the
/// proof of access to the server. Once any administrator is enrolled it writes nothing.
/// </summary>
public sealed class BootstrapInviteService : IHostedService
{
    // The user list may not be loaded yet when the host starts the plugin's services: try again for a while.
    private const int Attempts = 6;
    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(10);

    private readonly IUserManager _userManager;
    private readonly ISeedStore _seeds;
    private readonly IInviteStore _invites;
    private readonly ILogger<BootstrapInviteService> _logger;
    private readonly CancellationTokenSource _stop = new();
    private Task? _work;
    private bool _issued;

    /// <summary>
    /// Initializes a new instance of the <see cref="BootstrapInviteService"/> class.
    /// </summary>
    /// <param name="userManager">The user manager.</param>
    /// <param name="seeds">The seed store.</param>
    /// <param name="invites">The invitation code store.</param>
    /// <param name="logger">The logger.</param>
    public BootstrapInviteService(IUserManager userManager, ISeedStore seeds, IInviteStore invites, ILogger<BootstrapInviteService> logger)
    {
        _userManager = userManager;
        _seeds = seeds;
        _invites = invites;
        _logger = logger;
    }

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _work = Task.Run(() => RunAsync(_stop.Token), CancellationToken.None);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        if (_work is not null)
        {
            try
            {
                await _work.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Stopping.
            }
        }
    }

    /// <summary>
    /// Generates and logs the start-up codes if they are needed.
    /// </summary>
    /// <param name="ttl">The lifetime of the codes.</param>
    /// <returns><c>true</c> if the user list was available (whether or not a code was needed), <c>false</c> if there are no users yet.</returns>
    public bool TryIssue(TimeSpan ttl)
    {
        if (!_seeds.IsAvailable || !_invites.IsAvailable)
        {
            return true;
        }

        var admins = _userManager.GetUsers()
            .Where(u => u.HasPermission(PermissionKind.IsAdministrator) && !u.HasPermission(PermissionKind.IsDisabled))
            .ToList();
        if (!_userManager.GetUsers().Any())
        {
            return false;
        }

        if (_issued || admins.Count == 0 || admins.Any(a => _seeds.IsEnabled(a.Id)))
        {
            return true;
        }

        _issued = true;
        foreach (var admin in admins)
        {
            var invite = _invites.Create(admin.Id, ttl);
            _logger.LogWarning(
                "TwoFactor: no administrator has an authenticator yet. Start-up invitation code for administrator '{User}': {Code} (valid until {ExpiresAt:u}). Use it on the login page to enroll; it is shown only now.",
                admin.Username,
                invite.Code,
                invite.ExpiresAt);
        }

        return true;
    }

    private async Task RunAsync(CancellationToken token)
    {
        try
        {
            for (var attempt = 0; attempt < Attempts; attempt++)
            {
                if (TryIssue(Plugin.Instance?.Configuration.InviteTtl ?? TimeSpan.FromHours(24)))
                {
                    return;
                }

                await Task.Delay(RetryDelay, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TwoFactor: could not generate the start-up invitation codes.");
        }
    }
}
