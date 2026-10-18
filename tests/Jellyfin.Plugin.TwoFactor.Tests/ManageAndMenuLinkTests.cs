using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Jellyfin.Plugin.TwoFactor.Hosting;
using Jellyfin.Plugin.TwoFactor.Storage;
using Jellyfin.Plugin.TwoFactor.Tickets;
using Jellyfin.Plugin.TwoFactor.Totp;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public sealed class ManageAndMenuLinkTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tf-tests-" + Guid.NewGuid().ToString("N"));
    private readonly DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1_000_000_000);
    private readonly SeedCipher _cipher = new(RandomNumberGenerator.GetBytes(32));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    private FileSeedStore Open() => new(_dir, _cipher, NullLogger.Instance);

    // ---- seed store: TryReplace and Remove ----

    [Fact]
    public void TryReplace_SwapsTheSeed_AndTheOldOneStopsWorking()
    {
        var store = Open();
        var user = Guid.NewGuid();
        var oldSecret = TotpService.GenerateSecret();
        var newSecret = TotpService.GenerateSecret();
        var counter = TotpService.GetCounter(_now);
        store.TryEnroll(user, oldSecret, counter, TotpOptions.Default);

        Assert.True(store.TryReplace(user, newSecret, counter + 1, TotpOptions.Default));

        Assert.False(store.TryAcceptCode(user, TotpService.ComputeCode(oldSecret, counter + 2), _now.AddSeconds(60)));
        Assert.True(store.TryAcceptCode(user, TotpService.ComputeCode(newSecret, counter + 2), _now.AddSeconds(60)));
    }

    [Fact]
    public void TryReplace_BurnsTheConfirmationCode_AndSurvivesReload()
    {
        var store = Open();
        var user = Guid.NewGuid();
        var newSecret = TotpService.GenerateSecret();
        var counter = TotpService.GetCounter(_now);
        store.TryEnroll(user, TotpService.GenerateSecret(), counter, TotpOptions.Default);
        store.TryReplace(user, newSecret, counter + 1, TotpOptions.Default);

        var reloaded = Open();
        Assert.False(reloaded.TryAcceptCode(user, TotpService.ComputeCode(newSecret, counter + 1), _now.AddSeconds(30)));
        Assert.True(reloaded.TryAcceptCode(user, TotpService.ComputeCode(newSecret, counter + 2), _now.AddSeconds(60)));
    }

    [Fact]
    public void TryReplace_RefusesUsersWithoutAnEnabledSeed()
    {
        var store = Open();
        Assert.False(store.TryReplace(Guid.NewGuid(), TotpService.GenerateSecret(), 1, TotpOptions.Default));
    }

    [Fact]
    public void Remove_DeletesTheEntry_SoTheUserCanEnrollAgain()
    {
        var store = Open();
        var user = Guid.NewGuid();
        var other = Guid.NewGuid();
        var counter = TotpService.GetCounter(_now);
        store.TryEnroll(user, TotpService.GenerateSecret(), counter, TotpOptions.Default);
        store.TryEnroll(other, TotpService.GenerateSecret(), counter, TotpOptions.Default);

        Assert.True(store.Remove(user));
        Assert.False(store.Remove(user));
        Assert.False(store.IsEnabled(user));
        Assert.True(store.IsEnabled(other));
        Assert.True(store.TryEnroll(user, TotpService.GenerateSecret(), counter, TotpOptions.Default));

        var reloaded = Open();
        Assert.True(reloaded.IsEnabled(user));
        Assert.True(reloaded.IsEnabled(other));
    }

    [Fact]
    public void Remove_AlsoClearsAnEntryThatCannotBeDecrypted()
    {
        var user = Guid.NewGuid();
        Open().TryEnroll(user, TotpService.GenerateSecret(), 1, TotpOptions.Default);

        var wrongKey = new FileSeedStore(_dir, new SeedCipher(RandomNumberGenerator.GetBytes(32)), NullLogger.Instance);
        Assert.True(wrongKey.IsEnabled(user));
        Assert.True(wrongKey.Remove(user));
        Assert.False(wrongKey.IsEnabled(user));
        Assert.True(wrongKey.TryEnroll(user, TotpService.GenerateSecret(), 1, TotpOptions.Default));
    }

    // ---- tickets ----

    [Fact]
    public void RotationTickets_AreMarked_AndLoginTicketsAreNot()
    {
        var store = new TicketStore(TimeProvider.System);
        var user = Guid.NewGuid();
        var rotation = store.Get(store.Issue(user, "ana", "1.1.1.1", "d", "n", false, isRotation: true), "1.1.1.1", "d");
        var login = store.Get(store.Issue(user, "ana", "1.1.1.1", "d", "n", false), "1.1.1.1", "d");

        Assert.True(rotation!.IsRotation);
        Assert.False(login!.IsRotation);
    }

    // ---- menu link in config.json ----

    private const string MenuLinkUrl = "../TwoFactor/Manage";

    [Fact]
    public void InjectMenuLink_AddsTheEntry_KeepingTheOtherSettings()
    {
        var result = WebIndexMiddleware.InjectMenuLink("{\"themes\":[],\"menuLinks\":[{\"name\":\"Docs\",\"url\":\"https://x.test\"}],\"multiserver\":false}");

        var root = JsonNode.Parse(result)!;
        var links = root["menuLinks"]!.AsArray();
        Assert.Equal(3, links.Count);
        Assert.Equal("Docs", links[0]!["name"]!.ToString());
        Assert.Equal("Verificación en dos pasos", links[1]!["name"]!.ToString());
        Assert.Equal(MenuLinkUrl, links[1]!["url"]!.ToString());
        Assert.Equal("../TwoFactor/Admin", links[2]!["url"]!.ToString());
        Assert.False((bool)root["multiserver"]!);
        Assert.Contains("Verificación en dos pasos", result);
    }

    [Fact]
    public void InjectMenuLink_CreatesMenuLinks_WhenMissing()
    {
        var root = JsonNode.Parse(WebIndexMiddleware.InjectMenuLink("{\"multiserver\":false}"))!;
        Assert.Equal(2, root["menuLinks"]!.AsArray().Count);
    }

    [Fact]
    public void InjectMenuLink_IsIdempotent()
    {
        var once = WebIndexMiddleware.InjectMenuLink("{\"menuLinks\":[]}");
        Assert.Equal(once, WebIndexMiddleware.InjectMenuLink(once));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[1,2]")]
    [InlineData("{\"menuLinks\":\"oops\"}")]
    public void InjectMenuLink_LeavesAnythingUnexpectedAlone(string json)
    {
        Assert.Equal(json, WebIndexMiddleware.InjectMenuLink(json));
    }

    [Theory]
    [InlineData("/web/config.json", true)]
    [InlineData("/jellyfin/web/config.json", true)]
    [InlineData("/web/CONFIG.JSON", true)]
    [InlineData("/config.json", false)]
    [InlineData("/web/other.json", false)]
    public void IsConfigPath_OnlyMatchesTheWebClientConfig(string path, bool expected)
    {
        Assert.Equal(expected, WebIndexMiddleware.IsConfigPath(new PathString(path)));
    }

    private sealed class NoSeeds : ISeedStore
    {
        public bool IsAvailable => true;

        public bool IsEnabled(Guid userId) => throw new NotSupportedException();

        public bool TryEnroll(Guid userId, byte[] secret, long acceptedCounter, TotpOptions options) => throw new NotSupportedException();

        public bool TryAcceptCode(Guid userId, string? code, DateTimeOffset now) => throw new NotSupportedException();

        public bool TryReplace(Guid userId, byte[] secret, long acceptedCounter, TotpOptions options) => throw new NotSupportedException();

        public bool Remove(Guid userId) => throw new NotSupportedException();
    }

    [Fact]
    public async Task ConfigJson_GetsTheMenuLink_WithConsistentHeaders()
    {
        const string body = "{\"menuLinks\":[]}";
        var middleware = new WebIndexMiddleware(
            async context =>
            {
                context.Response.ContentType = "application/json";
                context.Response.ContentLength = Encoding.UTF8.GetByteCount(body);
                context.Response.Headers.ETag = "\"abc\"";
                await context.Response.WriteAsync(body);
            },
            new NoSeeds(),
            new TotpSettings(TotpOptions.Default, true),
            NullLogger<WebIndexMiddleware>.Instance);
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Path = "/web/config.json";
        context.Response.Body = new MemoryStream();

        await middleware.InvokeAsync(context);

        context.Response.Body.Position = 0;
        var text = new StreamReader(context.Response.Body, Encoding.UTF8).ReadToEnd();
        Assert.Contains(MenuLinkUrl, text);
        Assert.Equal(Encoding.UTF8.GetByteCount(text), context.Response.ContentLength);
        Assert.False(context.Response.Headers.ContainsKey("ETag"));
    }
}
