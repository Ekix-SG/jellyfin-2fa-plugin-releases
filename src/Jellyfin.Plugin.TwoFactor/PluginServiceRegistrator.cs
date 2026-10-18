using System;
using System.IO;
using Jellyfin.Plugin.TwoFactor.Hosting;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Tickets;
using Jellyfin.Plugin.TwoFactor.Totp;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactor;

/// <summary>
/// Registers the plugin services in the server container.
/// </summary>
public class PluginServiceRegistrator : IPluginServiceRegistrator
{
    /// <inheritdoc />
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton(TimeProvider.System);
        serviceCollection.AddSingleton<TicketStore>();
        serviceCollection.AddSingleton<LoginThrottle>();
        serviceCollection.AddTransient<IStartupFilter, LoginRedirectStartupFilter>();
        serviceCollection.AddSingleton(sp =>
        {
            var policy = PasswordLoginPolicy.FromEnvironment(Environment.GetEnvironmentVariable, out var error);
            if (error is not null)
            {
                sp.GetRequiredService<ILoggerFactory>().CreateLogger<PluginServiceRegistrator>()
                    .LogError("TwoFactor: {Problem}", error);
            }

            return policy;
        });
        serviceCollection.AddSingleton(sp =>
        {
            var valid = TotpOptions.TryFromEnvironment(Environment.GetEnvironmentVariable, out var options, out var errors);
            var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger<PluginServiceRegistrator>();
            foreach (var error in errors)
            {
                logger.LogError("TwoFactor: {Problem} Logins through the two-factor page are refused until it is fixed.", error);
            }

            if (valid)
            {
                logger.LogInformation(
                    "TwoFactor: new enrollments use {Digits} digits, {Algorithm}, {Period} s. Existing seeds keep the values they were enrolled with.",
                    options.Digits,
                    options.AlgorithmName,
                    options.PeriodSeconds);
            }

            return new TotpSettings(options, valid);
        });
        serviceCollection.AddSingleton<IInviteStore>(sp =>
        {
            var paths = sp.GetRequiredService<IApplicationPaths>();
            var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger<FileInviteStore>();

            // Same key as the seeds (the error for a missing key is already logged by the seed store).
            SeedCipher.TryCreateFromBase64(Environment.GetEnvironmentVariable(SeedCipher.KeyEnvironmentVariable), out var cipher);
            return new FileInviteStore(Path.Combine(paths.PluginConfigurationsPath, "TwoFactor"), cipher, sp.GetRequiredService<TimeProvider>(), logger);
        });
        serviceCollection.AddHostedService<BootstrapInviteService>();
        serviceCollection.AddSingleton<ISeedStore>(sp =>
        {
            var paths = sp.GetRequiredService<IApplicationPaths>();
            var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger<FileSeedStore>();

            SeedCipher.TryCreateFromBase64(Environment.GetEnvironmentVariable(SeedCipher.KeyEnvironmentVariable), out var cipher);
            if (cipher is null)
            {
                logger.LogError(
                    "TwoFactor: the environment variable {Variable} is missing or invalid. It must be standard Base64 text that decodes to exactly 32 bytes (44 characters). Logins through the two-factor page are refused and no seed is read or written until it is fixed.",
                    SeedCipher.KeyEnvironmentVariable);
            }

            return new FileSeedStore(Path.Combine(paths.PluginConfigurationsPath, "TwoFactor"), cipher, logger);
        });
    }
}
