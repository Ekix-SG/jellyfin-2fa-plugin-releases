using Jellyfin.Plugin.TwoFactor.Tickets;
using Microsoft.Extensions.Time.Testing;

namespace Jellyfin.Plugin.TwoFactor.Tests;

public class TicketStoreTests
{
    private readonly FakeTimeProvider _time = new(DateTimeOffset.FromUnixTimeSeconds(1_000_000_000));
    private readonly Guid _user = Guid.NewGuid();

    private (TicketStore Store, string Token) Create(bool enroll = false)
    {
        var store = new TicketStore(_time);
        var token = store.Issue(_user, "ana", "10.0.0.5", "device-1", "Firefox", enroll);
        Assert.NotNull(token);
        return (store, token!);
    }

    [Fact]
    public void Token_IsLongAndUnique()
    {
        var store = new TicketStore(_time);
        var a = store.Issue(_user, "ana", "1.1.1.1", "d", "n", false)!;
        var b = store.Issue(_user, "ana", "1.1.1.1", "d", "n", false)!;
        Assert.NotEqual(a, b);
        Assert.True(a.Length >= 43);
    }

    [Fact]
    public void Get_ReturnsTicketForMatchingBinding()
    {
        var (store, token) = Create();
        var ticket = store.Get(token, "10.0.0.5", "device-1");
        Assert.NotNull(ticket);
        Assert.Equal(_user, ticket!.UserId);
    }

    [Theory]
    [InlineData("10.0.0.6", "device-1")]
    [InlineData("10.0.0.5", "device-2")]
    public void Get_RejectsWrongIpOrDevice(string ip, string device)
    {
        var (store, token) = Create();
        Assert.Null(store.Get(token, ip, device));
        // A mismatching request does not destroy the legitimate ticket.
        Assert.NotNull(store.Get(token, "10.0.0.5", "device-1"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("nope")]
    public void Get_RejectsUnknownTokens(string? token)
    {
        var (store, _) = Create();
        Assert.Null(store.Get(token, "10.0.0.5", "device-1"));
    }

    [Fact]
    public void Ticket_ExpiresAfterTwoMinutes()
    {
        var (store, token) = Create();
        _time.Advance(TimeSpan.FromSeconds(119));
        Assert.NotNull(store.Get(token, "10.0.0.5", "device-1"));
        _time.Advance(TimeSpan.FromSeconds(1));
        Assert.Null(store.Get(token, "10.0.0.5", "device-1"));
    }

    [Fact]
    public void Consume_IsSingleUse()
    {
        var (store, token) = Create();
        Assert.True(store.Consume(token));
        Assert.False(store.Consume(token));
        Assert.Null(store.Get(token, "10.0.0.5", "device-1"));
    }

    [Fact]
    public void FifthFailedAttempt_DestroysTheTicket()
    {
        var (store, token) = Create();
        for (int i = 0; i < TicketStore.MaxFailedAttempts - 1; i++)
        {
            store.RegisterFailure(token);
            Assert.NotNull(store.Get(token, "10.0.0.5", "device-1"));
        }

        store.RegisterFailure(token);
        Assert.Null(store.Get(token, "10.0.0.5", "device-1"));
        Assert.False(store.Consume(token));
    }

    [Fact]
    public void PendingSecret_IsCreatedOnceAndReused()
    {
        var (store, token) = Create(enroll: true);
        var ticket = store.Get(token, "10.0.0.5", "device-1")!;
        var first = store.GetOrCreatePendingSecret(ticket, () => new byte[] { 1, 2, 3 });
        var second = store.GetOrCreatePendingSecret(ticket, () => new byte[] { 9, 9, 9 });
        Assert.Same(first, second);
    }

    [Fact]
    public void Store_RefusesToGrowWithoutBound()
    {
        var store = new TicketStore(_time);
        for (int i = 0; i < 1000; i++)
        {
            Assert.NotNull(store.Issue(_user, "ana", "1.1.1.1", "d", "n", false));
        }

        Assert.Null(store.Issue(_user, "ana", "1.1.1.1", "d", "n", false));
        _time.Advance(TimeSpan.FromMinutes(3));
        Assert.NotNull(store.Issue(_user, "ana", "1.1.1.1", "d", "n", false));
    }
}
