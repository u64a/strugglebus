using System.Text.Json;
using Xunit;

namespace StruggleBusMonitor.Tests;

public class HostStatusTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);

    private const string Full = """
        {"sb_host_status":{"v":1,"host":"office1","agent":"host-office1-host","version":"1.4.0","serial":12,
          "started_at":"2026-11-24T08:00:00Z","interval_s":3600,"state":"online","account":"sbworker","dedicated":true,
          "engines":[{"name":"claude","version":"2.1","signed_in":true,"default":true},{"name":"ghcp","version":"1.0","signed_in":false},{"name":"other"}],
          "workers":{"busy":2,"max":4,"claiming":0},"held_clones":1,"outbox":3,
          "fleet":{"source":"bus","serial":7,"coordinators":["coord-one"],"state":"accepted"},
          "update":null,"last_command":null,"problem":{"code":"disk-low","text":"The disk is nearly full."},
          "warnings":["not-dedicated","isolation-weak","something-new"]}}
        """;

    private static HostStatus? Parse(string json, string author = "host-office1-host") =>
        HostStatusParser.FromMetadata(JsonDocument.Parse(json).RootElement, author);

    private static BusAgent Agent(string name, DateTimeOffset? seen) => new("id-" + name, name, "", "", "seen", seen);

    [Fact]
    public void AFullStatusIsRead()
    {
        var status = Parse(Full)!;

        Assert.Equal(("office1", "host-office1-host", "1.4.0", "online", "sbworker"),
            (status.Host, status.Agent, status.Version, status.State, status.Account));
        Assert.Equal((2, 4, 1, 3, 7L), (status.Busy, status.Max, status.HeldClones, status.Outbox, status.FleetSerial));
        Assert.Equal([new HostEngine("claude", "2.1", true), new HostEngine("ghcp", "1.0", false), new HostEngine("other", "", null)], status.Engines);
        Assert.Equal("The disk is nearly full.", status.ProblemText);
        Assert.Equal(["not-dedicated", "isolation-weak", "something-new"], status.Warnings);
    }

    [Theory]
    [InlineData("""{}""")]
    [InlineData("""{"sb_host_status":"online"}""")]
    [InlineData("""{"sb_host_status":{"v":2,"agent":"host-office1-host"}}""")]
    [InlineData("""{"sb_host_status":{"v":"1","agent":"host-office1-host"}}""")]
    [InlineData("""{"sb_host_status":{"v":1}}""")]
    [InlineData("""{"sb_host_status":{"v":1,"agent":"someone-else-host"}}""")]
    [InlineData("""[1,2,3]""")]
    public void AnythingThatIsNotThisHostsOwnVersionOneStatusIsIgnored(string json) =>
        Assert.Null(Parse(json));

    [Fact]
    public void NoMetadataMeansNoStatus() =>
        Assert.Null(HostStatusParser.FromMetadata(null, "host-office1-host"));

    [Fact]
    public void WrongTypesAndHostileTextFallBackSafely()
    {
        var longText = new string('x', 500);
        var status = Parse("""
            {"sb_host_status":{"v":1,"agent":"host-office1-host","host":42,"version":"1.0\u0007\n<b>","state":"rm -rf",
              "account":"LONG","engines":"claude","workers":{"busy":-5,"max":100000},"held_clones":"many",
              "fleet":"none","problem":"broken","warnings":[7,"  spaced  ",null]}}
            """.Replace("LONG", longText))!;

        Assert.Equal("", status.Host);
        Assert.Equal("1.0<b>", status.Version);
        Assert.Equal("unknown", status.State);
        Assert.Equal(121, status.Account.Length);
        Assert.EndsWith("…", status.Account);
        Assert.Empty(status.Engines);
        Assert.Equal((0, 999, 0), (status.Busy, status.Max, status.HeldClones));
        Assert.Null(status.FleetSerial);
        Assert.Equal("", status.ProblemText);
        Assert.Equal(["spaced"], status.Warnings);
    }

    [Fact]
    public void LongListsAreCut()
    {
        var engines = string.Join(",", Enumerable.Range(0, 20).Select(index => """{"name":"engineN"}""".Replace("N", index.ToString())));
        var status = Parse("""{"sb_host_status":{"v":1,"agent":"host-office1-host","engines":[ENGINES]}}""".Replace("ENGINES", engines))!;

        Assert.Equal(8, status.Engines.Count);
    }

    [Fact]
    public void OnlyAgentsNamedAsHostsAreListed()
    {
        var agents = new[] { Agent("host-b-host", null), Agent("build-agent", null), Agent("-host", null), Agent("host-a-host", null), Agent("host-a-worker1", null) };

        Assert.Equal(["host-a-host", "host-b-host"], HostsLogic.HostAgents(agents).Select(agent => agent.Name));
        Assert.Equal(HostsLogic.MaxHosts, HostsLogic.HostAgents(Enumerable.Range(0, 100).Select(index => Agent($"host-{index:000}-host", null))).Count);
    }

    [Fact]
    public void TheNewestStatusFromThatHostWins()
    {
        var old = Parse(Full)! with { Version = "1.3.0" };
        var newest = Parse(Full)!;
        var other = Parse(Full)! with { Version = "9.9.9" };
        BusMessage Message(long seq, string agent, HostStatus? status) => new(seq, "worker-hosts", agent, "line", "status", Now, null, status);

        var messages = new[] { Message(5, "host-office1-host", newest), Message(3, "host-office1-host", old), Message(9, "host-other-host", other), Message(8, "host-office1-host", null) };

        Assert.Same(newest, HostsLogic.Latest(messages, "host-office1-host"));
        Assert.Null(HostsLogic.Latest(messages, "host-nobody-host"));
    }

    [Theory]
    [InlineData(10, true)]
    [InlineData(90, true)]
    [InlineData(91, false)]
    public void AHostIsAliveWhenTheBusSawItInTheLastNinetySeconds(int secondsAgo, bool alive) =>
        Assert.Equal(alive, HostsLogic.IsAlive(Now.AddSeconds(-secondsAgo), Now));

    [Fact]
    public void AHostNeverSeenIsNotAlive() => Assert.False(HostsLogic.IsAlive(null, Now));

    [Theory]
    [InlineData(true, "online", "ONLINE", "Ok")]
    [InlineData(true, "paused", "PAUSED", "Warn")]
    [InlineData(true, "needs-sign-in", "NEEDS SIGN-IN", "Warn")]
    [InlineData(true, "needs-fleet", "NOT IN THE FLEET YET", "Warn")]
    [InlineData(true, "unknown", "UNKNOWN STATE", "Warn")]
    [InlineData(true, null, "NO STATUS YET", "Warn")]
    [InlineData(false, "online", "NOT RESPONDING", "Off")]
    [InlineData(false, null, "NOT RESPONDING", "Off")]
    public void TheBadgePutsNotRespondingAheadOfWhatTheHostLastSaid(bool alive, string? state, string label, string tone) =>
        Assert.Equal((label, tone), HostsLogic.Badge(alive, state));

    [Fact]
    public void ARespondingHostsRowSaysWhatItIsDoing()
    {
        var row = HostsLogic.Row(Agent("host-office1-host", Now.AddSeconds(-5)), Parse(Full), Now);

        Assert.Equal(("office1", "ONLINE", "Ok"), (row.Name, row.StateLabel, row.Tone));
        Assert.Equal("2 of 4 workers busy  ·  version 1.4.0  ·  claude signed in, ghcp needs sign-in, other  ·  runs as sbworker  ·  1 kept for unsaved work  ·  3 replies waiting to post", row.Meta);
        Assert.True(row.HasAlerts);
        Assert.Equal(
            [
                "Problem: The disk is nearly full.",
                HostsLogic.WarningText("not-dedicated"),
                HostsLogic.WarningText("isolation-weak"),
                "Warning: something-new"
            ],
            row.Alerts.Split(Environment.NewLine));
        Assert.Contains("workers can reach everything that person can", row.Alerts);
    }

    [Fact]
    public void ASilentHostSaysWhenItWasLastSeenAndKeepsItsLastDetails()
    {
        var row = HostsLogic.Row(Agent("host-office1-host", Now.AddMinutes(-20)), Parse(Full), Now);

        Assert.Equal(("NOT RESPONDING", "Off"), (row.StateLabel, row.Tone));
        Assert.StartsWith(FeedLogic.PresenceLabel(Now.AddMinutes(-20), Now) + "  ·  2 of 4 workers busy", row.Meta);
    }

    [Fact]
    public void AHostWithNoStatusYetIsNamedFromItsAgent()
    {
        var row = HostsLogic.Row(Agent("host-lab2-host", Now), null, Now);

        Assert.Equal(("host-lab2", "NO STATUS YET", "Warn", "", false), (row.Name, row.StateLabel, row.Tone, row.Meta, row.HasAlerts));
    }

    [Fact]
    public void AQuietHealthyHostHasAShortRow()
    {
        var status = Parse("""{"sb_host_status":{"v":1,"agent":"host-office1-host","state":"online","workers":{"busy":0,"max":2}}}""");
        var row = HostsLogic.Row(Agent("host-office1-host", Now), status, Now);

        Assert.Equal(("host-office1", "0 of 2 workers busy", false), (row.Name, row.Meta, row.HasAlerts));
    }

    [Fact]
    public void TheConfirmationCodeIsEightHexOfAgentIdThenRequestId()
    {
        // The same value the bus's own test pins, so the three sides cannot drift apart.
        Assert.Equal("6be98e36", HostsLogic.ConfirmationCode("3b283d99-7521-4216-aceb-d39e6b5d5402", "11111111-2222-4333-8444-555555555555"));
        Assert.NotEqual(
            HostsLogic.ConfirmationCode("a", "b"),
            HostsLogic.ConfirmationCode("b", "a"));
    }

    [Fact]
    public void AHostThatJoinedWithACodeShowsItsConfirmationCodeAndWhereItCameFrom()
    {
        var agent = new BusAgent("3b283d99-7521-4216-aceb-d39e6b5d5402", "host-office1-host", "", "", "seen", Now);
        ManagedServicePrincipal Principal(string name, string? requestId, string? from) => new("spn-" + name, name, name, "enabled", 0, [], requestId, from);
        var principals = new[]
        {
            Principal("host-lab2", "99999999-2222-4333-8444-555555555555", "10.0.0.9"),
            Principal("host-office1", "11111111-2222-4333-8444-555555555555", "10.0.0.5")
        };

        var principal = HostsLogic.PrincipalFor(agent, principals);
        var row = HostsLogic.Row(agent, null, Now, principal);

        Assert.Equal("host-office1", principal?.Name);
        Assert.True(row.HasJoined);
        Assert.Equal("Confirmation code 6be98e36, redeemed from 10.0.0.5. It must match the code the installer printed on that PC.", row.Joined);
        Assert.Equal("Confirmation code 6be98e36. It must match the code the installer printed on that PC.",
            HostsLogic.JoinedText(agent.Id, "11111111-2222-4333-8444-555555555555", null));
    }

    [Fact]
    public void AHostWithoutAHostCodeHasNoConfirmationCode()
    {
        var agent = new BusAgent("id", "host-office1-host", "", "", "seen", Now);
        var byHand = new ManagedServicePrincipal("spn", "host-office1", "host-office1", "enabled", 0, []);

        Assert.Null(HostsLogic.PrincipalFor(agent, []));
        Assert.Equal("", HostsLogic.JoinedText(agent.Id, null, "10.0.0.5"));
        Assert.Equal("", HostsLogic.JoinedText(agent.Id, "", null));
        Assert.False(HostsLogic.Row(agent, null, Now, byHand).HasJoined);
        Assert.False(HostsLogic.Row(agent, null, Now).HasJoined);
    }

    [Fact]
    public void TheSummaryCountsSilentHostsAndThoseNeedingAttention()
    {
        HostRow Row(string tone, string alerts = "") => new() { Name = "h", StateLabel = "S", Tone = tone, Alerts = alerts };

        Assert.Equal("No worker hosts yet. A host appears here once it has joined the bus.", HostsLogic.Summary([]));
        Assert.Equal("1 host.", HostsLogic.Summary([Row("Ok")]));
        Assert.Equal("4 hosts, 1 not responding, 2 needing attention.",
            HostsLogic.Summary([Row("Ok"), Row("Off"), Row("Warn"), Row("Ok", "Warning: x")]));
    }
}
