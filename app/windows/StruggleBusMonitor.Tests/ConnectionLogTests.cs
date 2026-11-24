using System.IO;
using System.Net.Http;

namespace StruggleBusMonitor.Tests;

public class ConnectionLogTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 18, 0, 0, 0, TimeSpan.Zero);

    private static BusMessage Notice(string version, DateTimeOffset at) => new(1, "ops", "bus",
        $"Strugglebus maintenance: release {version} is scheduled for installation at {at.UtcDateTime:yyyy-MM-ddTHH:mm:ss}+00:00. The bus will disconnect briefly and agents should reconnect.",
        "status", Start);

    [Fact]
    public void AnOutageIsOneLineDownAndOneLineUp()
    {
        var tracker = new ConnectionTracker();
        Assert.Equal("Connected to the bus.", tracker.ReportUp(Start)!.Text);
        Assert.Null(tracker.ReportUp(Start.AddSeconds(5)));

        var down = tracker.ReportDown(Start.AddMinutes(1), "Connection refused\r\nsecond line");
        Assert.Equal("Bad", down!.Tone);
        Assert.Equal("Bus not reachable. Trying again automatically. (Connection refused second line)", down.Text);
        Assert.True(tracker.IsDown);
        Assert.Null(tracker.ReportDown(Start.AddMinutes(2), "still refused"));
        Assert.Null(tracker.ReportStopping(Start.AddMinutes(2)));

        var up = tracker.ReportUp(Start.AddMinutes(4).AddSeconds(12));
        Assert.Equal("Reconnected. Offline for 3m 12s.", up!.Text);
        Assert.False(tracker.IsDown);
    }

    [Fact]
    public void ARestartAndScheduledMaintenanceAreNamed()
    {
        var tracker = new ConnectionTracker();
        tracker.ReportUp(Start);
        Assert.Equal("Warn", tracker.ReportStopping(Start.AddSeconds(10))!.Tone);
        Assert.Equal("Reconnected after the bus restarted. Offline for 8s.", tracker.ReportUp(Start.AddSeconds(18))!.Text);

        var planned = Start.AddHours(2);
        var announced = tracker.ReportMessage(Notice("0.2.65", planned), Start.AddMinutes(1));
        Assert.StartsWith("Maintenance announced: release 0.2.65 installs at ", announced!.Text);
        Assert.Null(tracker.ReportMessage(Notice("0.2.65", planned), Start.AddMinutes(2)));
        Assert.Null(tracker.ReportMessage(new BusMessage(2, "ops", "a", "Strugglebus maintenance is fun", "chat", Start), Start));
        Assert.Null(tracker.ReportMessage(Notice("0.2.60", Start.AddDays(-3)), Start));

        // An outage well before the window is not blamed on the maintenance.
        tracker.ReportDown(Start.AddMinutes(30), "timeout");
        Assert.Equal("Reconnected. Offline for 1m 0s.", tracker.ReportUp(Start.AddMinutes(31))!.Text);

        tracker.ReportStopping(planned.AddSeconds(3));
        Assert.Equal("Reconnected after scheduled maintenance (release 0.2.65). Offline for 1h 5m.",
            tracker.ReportUp(planned.AddSeconds(3).AddMinutes(65))!.Text);
    }

    [Fact]
    public void FreezeAndBusVersionChangesAreReportedOnce()
    {
        var tracker = new ConnectionTracker();
        Assert.Null(tracker.ReportFrozen(Start, false));
        Assert.Equal("Bad", tracker.ReportFrozen(Start, true)!.Tone);
        Assert.Null(tracker.ReportFrozen(Start, true));
        Assert.Equal("Ok", tracker.ReportFrozen(Start, false)!.Tone);

        Assert.Null(tracker.ReportBus("0.2.64", Start, Start));
        Assert.Null(tracker.ReportBus("0.2.64", Start, Start.AddMinutes(1)));
        Assert.Contains("restarted", tracker.ReportBus("0.2.64", Start.AddMinutes(5), Start.AddMinutes(6))!.Text);
        Assert.Equal("The bus is now on version 0.2.65 (was 0.2.64).", tracker.ReportBus("0.2.65", Start.AddMinutes(9), Start.AddMinutes(10))!.Text);
    }

    [Fact]
    public void LogKeepsNewestFirstDropsRepeatsAndSurvivesAReload()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sbm-log-{Guid.NewGuid():N}", "connection-log.json");
        try
        {
            var log = ConnectionLog.LoadFromPath(path);
            Assert.False(log.Add(null));
            Assert.True(log.Add(new ConnectionEvent(Start, "Bad", "down")));
            Assert.False(log.Add(new ConnectionEvent(Start.AddSeconds(20), "Bad", "down")));
            Assert.True(log.Add(new ConnectionEvent(Start.AddMinutes(3), "Ok", "up")));
            for (var index = 0; index < ConnectionLog.Maximum + 5; index++)
                log.Add(new ConnectionEvent(Start.AddHours(1 + index), "Ok", $"event {index}"));

            var reloaded = ConnectionLog.LoadFromPath(path);
            Assert.Equal(ConnectionLog.Maximum, reloaded.Events.Count);
            Assert.Equal($"event {ConnectionLog.Maximum + 4}", reloaded.Events[0].Text);
            Assert.Contains("event 7", reloaded.ToText());

            reloaded.Clear();
            Assert.Empty(ConnectionLog.LoadFromPath(path).Events);

            File.WriteAllText(path, "{not json");
            Assert.Empty(ConnectionLog.LoadFromPath(path).Events);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, recursive: true);
        }
    }

    [Fact]
    public void ParsesAndFiltersTheBusLog()
    {
        // Shaped exactly like the StruggleBus 0.2.65 response.
        var log = BusApi.ParseBusLog("""
            {"version":"0.2.65","started_at":"2026-11-18T00:00:05Z","entries":[
              {"ts":"2026-11-18T01:00:00Z","source":"request","level":"warning","event":"POST /api/mobile/grants",
               "subject":null,"actor":null,"status":401,"remote_address":"192.0.2.7","detail":"refused"},
              {"ts":"2026-11-18T00:30:00+00:00","source":"audit","level":"info","event":"blocked",
               "subject":"prox-manager","actor":"remote-admin:device:desk-pc","status":null,"remote_address":null,"detail":"agent lifecycle"},
              {"ts":"2026-11-18T00:00:06Z","source":"server","level":"error","event":"uvicorn.error",
               "subject":null,"actor":null,"status":null,"remote_address":null,"detail":"Exception in ASGI application"}]}
            """);

        Assert.Equal("0.2.65", log.Version);
        Assert.Equal(new DateTimeOffset(2026, 11, 18, 0, 0, 5, TimeSpan.Zero), log.StartedAt);
        Assert.Equal("HTTP 401  ·  from 192.0.2.7", log.Entries[0].Summary);
        Assert.Equal("prox-manager  ·  by remote-admin:device:desk-pc  ·  agent lifecycle", log.Entries[1].Summary);
        Assert.Equal(["Warn", "Muted", "Bad"], log.Entries.Select(entry => entry.Tone));

        Assert.Equal(2, BusLog.Filter(log.Entries, problemsOnly: true, null).Count);
        Assert.Equal("blocked", BusLog.Filter(log.Entries, false, "PROX audit").Single().Event);
        Assert.Empty(BusLog.Filter(log.Entries, true, "prox"));
        Assert.Contains("uvicorn.error", log.Entries[2].ToLine());
    }

    [Fact]
    public void OnlyFailuresThatWaitingCanFixAreRetried()
    {
        Assert.True(MonitorLogic.IsTransient(new HttpRequestException("refused")));
        Assert.True(MonitorLogic.IsTransient(new TaskCanceledException()));
        Assert.True(MonitorLogic.IsTransient(new BusApiException(503, "down", "down")));
        Assert.False(MonitorLogic.IsTransient(new BusApiException(401, "no", "no")));
        Assert.False(MonitorLogic.IsTransient(new InvalidOperationException("bug")));
        Assert.Equal(TimeSpan.FromSeconds(60), MonitorLogic.DecideStreamEnd(new StreamEnd(StreamEndKind.ProtocolFailure, "x"), 1).Delay);
        Assert.Equal(TimeSpan.FromSeconds(2), MonitorLogic.DecideStreamEnd(new StreamEnd(StreamEndKind.ServerStopping, "x"), 1).Delay);
    }
}
