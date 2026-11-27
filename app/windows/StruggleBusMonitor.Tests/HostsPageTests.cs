using System.IO;
using System.Net;
using System.Text.Json;
using System.Windows;

namespace StruggleBusMonitor.Tests;

/// <summary>The Hosts page's reading of the bus's answers, and what it says about each host.</summary>
public sealed class HostsPageLogicTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-27T04:01:00Z");

    private static string Contract(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Contracts", "host-status", name));

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    /// <summary>The bus's answer for one host whose snapshot is the contract's.</summary>
    private static string Answer(string snapshotFile = "snapshot-v2.json", string receivedAt = "2026-11-27T04:00:00Z") =>
        "{\"now\":\"2026-11-27T04:01:00Z\",\"hosts\":[{\"agent_id\":\"a-1\",\"agent\":\"host-box1-host\",\"marked_at\":\"x\",\"received_at\":\""
        + receivedAt + "\",\"snapshot\":" + Contract(snapshotFile) + "}]}";

    private static HostReport Report(string snapshotFile = "snapshot-v2.json", string receivedAt = "2026-11-27T04:00:00Z") =>
        Assert.Single(HostsParser.Status(Json(Answer(snapshotFile, receivedAt))).Hosts);

    [Fact]
    public void TheContractSnapshotIsReadWhole()
    {
        var status = HostsParser.Status(Json(Answer()));
        var report = Assert.Single(status.Hosts);
        var snapshot = report.Snapshot!;

        Assert.Equal(Now, status.Now);
        Assert.Equal(("a-1", "host-box1-host", DateTimeOffset.Parse("2026-11-27T04:00:00Z")), (report.AgentId, report.Agent, report.ReceivedAt));
        Assert.Equal(("box1", "online", "2026.11.24.2", "sbworker", 2, 12), (snapshot.Basic.Host, snapshot.Basic.State, snapshot.Basic.Version, snapshot.Basic.Account, snapshot.Basic.Busy, snapshot.Basic.Max));
        Assert.Equal([new HostWorker("w01", "ghcp", "claude-opus-5.5", 42), new HostWorker("w02", "claude", "claude-sonnet-5.5", 7)], snapshot.Running);
        Assert.Equal(new HostMachine(37.2, 21.0, 812.6, 48.0), snapshot.Machine);
        Assert.Equal(("ok", "worker-hosts", "claude-opus-5.5", "2026.11.28", "03:00"), (snapshot.BusState, snapshot.Channel, snapshot.Model, snapshot.UpdateVersion, snapshot.UpdateWhen));
        Assert.Equal(17, snapshot.Tasks.Single(task => task.Key == "finished").Value);
        Assert.Equal(7, snapshot.Tasks.Count);
        Assert.Equal(["isolation-weak"], snapshot.Basic.Warnings);
    }

    [Fact]
    public void WithoutTheGrantTheAccountWarningsAndChannelAreSimplyAbsent()
    {
        var snapshot = Report("snapshot-v2-device.json").Snapshot!;

        Assert.Equal((string.Empty, string.Empty), (snapshot.Basic.Account, snapshot.Channel));
        Assert.Empty(snapshot.Basic.Warnings);
        Assert.Equal("ok", snapshot.BusState);
    }

    [Fact]
    public void AnAnswerThatIsNotWhatWasExpectedGivesEmptyValuesAndNeverThrows()
    {
        var odd = HostsParser.Status(Json("""{"now":7,"hosts":[{"agent_id":"a","agent":"h","received_at":"not a time","snapshot":{"workers":{"running":[{"minutes":"x"}]},"machine":{"cpu_pct":"hot"},"tasks":[],"bus":7,"pwsh":"7.5.4"}},{"agent":"no id"},7,{"agent_id":"b","agent":"never reported","snapshot":null}]}"""));

        Assert.Equal(["a", "b"], odd.Hosts.Select(host => host.AgentId));
        var snapshot = odd.Hosts[0].Snapshot!;
        Assert.Null(odd.Hosts[0].ReceivedAt);
        Assert.Equal(new HostWorker("", "", "", 0), Assert.Single(snapshot.Running));
        Assert.Equal(new HostMachine(null, null, null, null), snapshot.Machine);
        Assert.Equal(("", "7.5.4", "unknown"), (snapshot.BusState, snapshot.Pwsh, snapshot.Basic.State));
        Assert.All(snapshot.Tasks, task => Assert.Equal(0, task.Value));
        Assert.Null(odd.Hosts[1].Snapshot);
        Assert.Empty(HostsParser.Status(Json("[]")).Hosts);
        Assert.Empty(HostsParser.History(Json("{}")));
    }

    [Fact]
    public void HistoryIsReadFromTheContractSampleAndASampleWithNoTimeIsLeftOut()
    {
        var others = """{"workers":{"busy":1}},{"received_at":"2026-11-27T04:01:00Z","machine":{}}""";
        var history = HostsParser.History(Json("{\"samples\":[" + Contract("sample-v2.json") + "," + others + "]}"));

        Assert.Equal(
            [new HostSample(DateTimeOffset.Parse("2026-11-27T04:00:00Z"), 2, 12, 37.2), new HostSample(Now, 0, 0, null)],
            history);
    }

    [Fact]
    public void ACardSaysWhatTheHostIsDoing()
    {
        var card = HostsPageLogic.Card(Report(), Now);

        Assert.Equal(("a-1", "box1", "ONLINE", "Ok"), (card.AgentId, card.Name, card.StateLabel, card.Tone));
        Assert.Equal("reported less than a minute ago", card.Seen);
        Assert.Equal("2 of 12 workers busy", card.Workers);
        Assert.Equal($"w01  ·  ghcp  ·  claude-opus-5.5  ·  42 min{Environment.NewLine}w02  ·  claude  ·  claude-sonnet-5.5  ·  7 min", card.Running);
        Assert.Equal("CPU 37%  ·  21.0 GB memory free  ·  812.6 GB disk free  ·  commit 48%", card.Machine);
        Assert.Equal("Since it started: 17 finished, 2 failed, 1 timed out, 3 refused", card.Tasks);
        Assert.Equal(
            "version 2026.11.24.2  ·  ghcp, claude signed in  ·  default model claude-opus-5.5  ·  PowerShell 7.6.10  ·  runs as sbworker  ·  channel #worker-hosts  ·  1 kept for unsaved work  ·  update to 2026.11.28 at 03:00  ·  updates from https://github.com/acme/mono#worker-host",
            card.Details);
        Assert.StartsWith("Warning: the host's account can change programs", card.Alerts);
        Assert.True(card.HasAlerts && card.HasRunning);
    }

    [Theory]
    [InlineData("2026-11-27T04:00:00Z", "ONLINE", "Ok", "reported less than a minute ago", "2 of 12 workers busy")]
    [InlineData("2026-11-27T03:58:30Z", "ONLINE", "Ok", "last reported 2 minutes ago", "2 of 12 workers busy")]
    [InlineData("2026-11-27T03:58:29Z", "NOT REPORTING", "Off", "last reported 2 minutes ago", "When it last reported: 2 of 12 workers busy")]
    [InlineData("2026-11-27T01:01:00Z", "NOT REPORTING", "Off", "last reported 3 hours ago", "When it last reported: 2 of 12 workers busy")]
    public void WhetherAHostIsReportingComesFromTheBusClock(string receivedAt, string label, string tone, string seen, string workers)
    {
        var card = HostsPageLogic.Card(Report(receivedAt: receivedAt), Now);

        Assert.Equal((label, tone, seen, workers), (card.StateLabel, card.Tone, card.Seen, card.Workers));
    }

    [Fact]
    public void AHostThatHasNeverReportedSaysSoAndShowsNothingElse()
    {
        var card = HostsPageLogic.Card(new HostReport("a-2", "host-new-host", null, null), Now);

        Assert.Equal(("host-new-host", "NO REPORT YET", "Warn", "It has not reported to the bus yet."), (card.Name, card.StateLabel, card.Tone, card.Seen));
        Assert.Equal((string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty), (card.Workers, card.Running, card.Machine, card.Tasks, card.Details, card.Alerts));
        Assert.False(card.HasAlerts || card.HasRunning || card.HasHistory);
    }

    [Fact]
    public void AStateOtherThanOnlineAndAProblemAreShown()
    {
        var snapshot = Report().Snapshot!;
        var troubled = snapshot with
        {
            Basic = snapshot.Basic with { State = "needs-sign-in", ProblemText = "An engine needs signing in.", Warnings = [] },
            BusState = "down"
        };

        var card = HostsPageLogic.Card(new HostReport("a", "h", Now, troubled), Now);

        Assert.Equal(("NEEDS SIGN-IN", "Warn"), (card.StateLabel, card.Tone));
        Assert.Equal($"Problem: An engine needs signing in.{Environment.NewLine}Problem: the host says it cannot reach the bus.", card.Alerts);
    }

    [Fact]
    public void FiguresNotMeasuredAndOutcomesThatHaveNotHappenedAreLeftOut()
    {
        Assert.Equal("CPU 4%  ·  commit 51%", HostsPageLogic.MachineLine(new HostMachine(4.4, null, null, 50.6)));
        Assert.Equal(string.Empty, HostsPageLogic.MachineLine(new HostMachine(null, null, null, null)));
        Assert.Equal("No tasks have ended since it started.", HostsPageLogic.TasksLine([KeyValuePair.Create("finished", 0)]));
    }

    [Fact]
    public void TheSummaryCountsHostsAndSaysWhatTheGrantWouldAdd()
    {
        var online = HostsPageLogic.Card(Report("snapshot-v2-device.json"), Now);
        var silent = HostsPageLogic.Card(Report(receivedAt: "2026-11-27T01:00:00Z"), Now);
        var waiting = HostsPageLogic.Card(new HostReport("a", "h", null, null), Now);

        Assert.Equal("No worker hosts are marked on this bus yet. Mark one on Admin, Worker hosts.", HostsPageLogic.Summary([], whole: true));
        Assert.Equal("1 host.", HostsPageLogic.Summary([online], whole: true));
        Assert.Equal("3 hosts, 1 not reporting, 1 needing attention.", HostsPageLogic.Summary([online, silent, waiting], whole: true));
        Assert.Equal(
            "1 host. Save operator access on Admin to also see each host's account, warnings and channel.",
            HostsPageLogic.Summary([online], whole: false));
    }

    [Fact]
    public void ThePageAsksTheBusAgainAfterHalfAMinute()
    {
        Assert.True(HostsPageLogic.IsStale(null, Now));
        Assert.False(HostsPageLogic.IsStale(Now.AddSeconds(-29), Now));
        Assert.True(HostsPageLogic.IsStale(Now.AddSeconds(-30), Now));
    }

    [Fact]
    public void ALineRunsLeftToRightOverTwelveHoursAndBottomToTop()
    {
        (DateTimeOffset, double?)[] samples =
        [
            (Now.AddHours(-13), 5), (Now.AddHours(-12), 0), (Now.AddHours(-6), 6), (Now.AddHours(-3), null),
            (Now, 12), (Now.AddMinutes(1), 3), (Now.AddHours(-1), 99)
        ];

        var line = HostsPageLogic.Line(samples, Now, top: 12);

        Assert.Equal(
            [new Point(0, 34), new Point(130, 17), new Point(260, 0), new Point(238.3, 0)],
            line);
        Assert.True(line.IsFrozen);
        Assert.Equal(new Point(260, 34), Assert.Single(HostsPageLogic.Line([(Now, 0)], Now, top: 0)));
    }

    [Fact]
    public void HistoryIsDrawnOnTheCardOnceThereAreTwoPoints()
    {
        var card = HostsPageLogic.Card(Report(), Now);
        HostSample[] samples = [new(Now.AddHours(-2), 3, 12, 40), new(Now.AddHours(-1), 6, 12, null), new(Now, 12, 12, 100)];

        HostsPageLogic.Draw(card, samples, Now);

        Assert.True(card.HasHistory);
        Assert.Equal(3, card.BusyLine.Count);
        Assert.Equal(2, card.CpuLine.Count);
        Assert.Equal(new Point(260, 0), card.BusyLine[2]);
        Assert.Equal("Last 12 hours: workers busy of 12 (bright line) and processor use (faint line)", card.HistoryLabel);

        HostsPageLogic.Draw(card, [samples[0]], Now);
        Assert.False(card.HasHistory);
        Assert.Equal("Not enough reports yet to draw the last 12 hours.", card.HistoryLabel);
        HostsPageLogic.Draw(card, [], Now);
        Assert.Empty(card.BusyLine);

        var never = HostsPageLogic.Card(new HostReport("a-2", "host-new-host", null, null), Now);
        HostsPageLogic.Draw(never, [], Now);
        Assert.Equal(string.Empty, never.HistoryLabel);
    }

    [Fact]
    public void MarkingSaysWhatItDoesBeforeItIsDone()
    {
        Assert.Contains("allowed to report its status and events", HostsPageLogic.MarkReview("host-box1-host", mark: true));
        Assert.Contains("status the bus holds for it is removed", HostsPageLogic.MarkReview("host-box1-host", mark: false));
        Assert.Equal("Mark host-box1-host as a worker host", HostsPageLogic.MarkHelloPrompt("host-box1-host", mark: true));
        Assert.Equal("Unmark host-box1-host as a worker host", HostsPageLogic.MarkHelloPrompt("host-box1-host", mark: false));
        Assert.Equal(("No longer a host", "Mark as host"), (HostsPageLogic.MarkLabel(true), HostsPageLogic.MarkLabel(false)));
    }
}

/// <summary>The bus calls behind the Hosts page.</summary>
public sealed class HostsBusApiTests
{
    private const string OneHost = """{"now":"2026-11-27T04:01:00Z","hosts":[{"agent_id":"a-1","agent":"host-box1-host","marked_at":"x","received_at":null,"snapshot":null}]}""";

    [Fact]
    public async Task WithoutTheGrantTheDeviceReadIsUsed()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json(OneHost);

        var status = await api.GetHostsStatusAsync(whole: false, CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal(("GET", "/api/mobile/hosts/status"), (request.Method, request.PathAndQuery));
        Assert.Equal("host-box1-host", Assert.Single(status.Hosts).Agent);
    }

    [Fact]
    public async Task TheWholeSnapshotIsAskedForWithTheGrantInTheBody()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json(OneHost);

        await api.GetHostsStatusAsync(whole: true, CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal(("POST", "/api/mobile/admin/hosts/status"), (request.Method, request.PathAndQuery));
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal(["grant_secret"], body.RootElement.EnumerateObject().Select(property => property.Name));
        Assert.False(string.IsNullOrEmpty(body.RootElement.GetProperty("grant_secret").GetString()));
    }

    [Fact]
    public async Task HistoryIsAskedForByAgentId()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("""{"now":"2026-11-27T04:01:00Z","agent_id":"a/1","samples":[{"received_at":"2026-11-27T04:00:00Z","workers":{"busy":2,"max":12},"machine":{"cpu_pct":37.2}}]}""");

        var history = await api.GetHostHistoryAsync("a/1", CancellationToken.None);

        Assert.Equal("/api/mobile/hosts/a%2F1/status/history", Assert.Single(harness.Bus.Requests).PathAndQuery);
        Assert.Equal(new HostSample(DateTimeOffset.Parse("2026-11-27T04:00:00Z"), 2, 12, 37.2), Assert.Single(history));
    }

    [Theory]
    [InlineData(true, "mark")]
    [InlineData(false, "unmark")]
    public async Task MarkingSendsExactlyWhatTheBusAccepts(bool mark, string action)
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"applied":true,"detail":"Agent is now a worker host.","target_label":"host-box1-host","state":"a worker host","secret":null}""");

        var result = await api.MarkHostAsync("a/1", "host-box1-host", mark, "enrolled before host codes", CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal(("POST", "/api/mobile/admin/agents/a%2F1/host"), (request.Method, request.PathAndQuery));
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal(
            ["action", "expected_name", "grant_secret", "reason", "request_id"],
            body.RootElement.EnumerateObject().Select(property => property.Name).Order());
        Assert.Equal(action, body.RootElement.GetProperty("action").GetString());
        Assert.Equal("host-box1-host", body.RootElement.GetProperty("expected_name").GetString());
        Assert.Matches("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", body.RootElement.GetProperty("request_id").GetString());
        Assert.Equal(("host-box1-host", true), (result.TargetLabel, result.Applied));
    }

    [Fact]
    public async Task TheFullLogIsAskedForWithTheGrantAndReadLikeTheOrdinaryOne()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled(withGrant: true);
        harness.Bus.Json("""{"version":"0.2.74","started_at":null,"entries":[{"ts":"2030-01-01T00:01:00Z","source":"host","level":"error","event":"fatal","subject":"host-box1-host","detail":"error=KeyError at=2030-01-01T00:00:59Z"}]}""");

        var log = await api.GetFullBusLogAsync(500, CancellationToken.None);

        var request = Assert.Single(harness.Bus.Requests);
        Assert.Equal(("POST", "/api/mobile/admin/logs/full"), (request.Method, request.PathAndQuery));
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal(500, body.RootElement.GetProperty("limit").GetInt32());
        Assert.Equal(["grant_secret", "limit"], body.RootElement.EnumerateObject().Select(property => property.Name).Order());
        var entry = Assert.Single(log.Entries);
        Assert.Equal(("host", "fatal", "host-box1-host", true), (entry.Source, entry.Event, entry.Subject, entry.IsProblem));
    }

    [Fact]
    public async Task WithoutTheGrantNoAdministratorReadIsSent()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();

        await Assert.ThrowsAsync<InvalidOperationException>(() => api.GetHostsStatusAsync(whole: true, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => api.GetFullBusLogAsync(10, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => api.MarkHostAsync("a", "n", true, "r", CancellationToken.None));

        Assert.Empty(harness.Bus.Requests);
    }

    [Fact]
    public async Task ABusThatDoesNotKnowHostsYetAnswers404()
    {
        var harness = new BusHarness();
        var api = harness.Enrolled();
        harness.Bus.Json("""{"detail":"Not Found"}""", HttpStatusCode.NotFound);

        var error = await Assert.ThrowsAsync<BusApiException>(() => api.GetHostsStatusAsync(whole: false, CancellationToken.None));

        Assert.Equal(404, error.StatusCode);
    }
}
