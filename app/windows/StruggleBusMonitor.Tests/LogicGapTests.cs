using Windows.Security.Credentials.UI;

namespace StruggleBusMonitor.Tests;

internal sealed class FakeUserConsent(UserConsentVerifierAvailability availability, UserConsentVerificationResult result) : IUserConsent
{
    public List<string> Prompts { get; } = [];

    public Task<UserConsentVerifierAvailability> CheckAvailabilityAsync() => Task.FromResult(availability);

    public Task<UserConsentVerificationResult> RequestVerificationAsync(string message)
    {
        Prompts.Add(message);
        return Task.FromResult(result);
    }
}

public sealed class WindowsHelloVerifyTests
{
    [Fact]
    public async Task VerifyAsync_IsTrueWhenTheOperatorConfirms()
    {
        var consent = new FakeUserConsent(UserConsentVerifierAvailability.Available, UserConsentVerificationResult.Verified);

        Assert.True(await new WindowsHello(consent).VerifyAsync("Block agent-one"));
        Assert.Equal(["Block agent-one"], consent.Prompts);
    }

    [Theory]
    [InlineData(UserConsentVerificationResult.Canceled)]
    [InlineData(UserConsentVerificationResult.RetriesExhausted)]
    [InlineData(UserConsentVerificationResult.DeviceBusy)]
    public async Task VerifyAsync_IsFalseForAnythingButAConfirmation(UserConsentVerificationResult result)
    {
        var consent = new FakeUserConsent(UserConsentVerifierAvailability.Available, result);

        Assert.False(await new WindowsHello(consent).VerifyAsync("Block agent-one"));
    }

    [Theory]
    [InlineData(UserConsentVerifierAvailability.NotConfiguredForUser, "Windows Hello is not set up for your Windows account.")]
    [InlineData(UserConsentVerifierAvailability.DisabledByPolicy, "Windows Hello is turned off on this PC by a policy.")]
    public async Task VerifyAsync_ExplainsWhyHelloCannotBeUsedAndNeverPrompts(UserConsentVerifierAvailability availability, string expected)
    {
        var consent = new FakeUserConsent(availability, UserConsentVerificationResult.Verified);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => new WindowsHello(consent).VerifyAsync("Block agent-one"));

        Assert.StartsWith(expected, error.Message);
        Assert.Empty(consent.Prompts);
    }

    [Fact]
    public async Task VerifyAsync_NamesAStateThisVersionDoesNotKnow()
    {
        var consent = new FakeUserConsent((UserConsentVerifierAvailability)99, UserConsentVerificationResult.Verified);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => new WindowsHello(consent).VerifyAsync("Block agent-one"));

        Assert.Equal("Windows Hello is unavailable (99).", error.Message);
    }

    [Fact]
    public void TheDefaultConstructorUsesTheWindowsPromptWithoutShowingIt() =>
        Assert.NotNull(new WindowsHello());
}

public sealed class LogicGapTests
{
    private static readonly DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(null, true)]
    [InlineData("  ", true)]
    [InlineData(" AGENT ", true)]
    [InlineData("box", true)]
    [InlineData("other", false)]
    public void MatchesAgent_LooksInNameAndHost(string? filter, bool expected) =>
        Assert.Equal(expected, FeedLogic.MatchesAgent(new BusAgent("a1", "agent-one", "", "Box-7", "seen", null), filter));

    [Fact]
    public void FeedQuery_EmptyHasNoParts()
    {
        Assert.True(FeedQuery.Empty.IsEmpty);
        Assert.False(new FeedQuery("", null, "ops").IsEmpty);
        Assert.Equal(FeedQuery.Empty, FeedLogic.ParseQuery(null));
    }

    [Fact]
    public void ParseQuery_KeepsBarePrefixesAsWordsAndDropsAnEmptyChannel()
    {
        Assert.Equal(new FeedQuery("from: in:", null, null), FeedLogic.ParseQuery("from: in:"));
        Assert.Equal(new FeedQuery("", "", null), FeedLogic.ParseQuery("FROM:@ IN:#"));
    }

    [Fact]
    public void WaitingOnOperator_ListsSeveralQuestionsOldestFirst()
    {
        BusMessage Question(long seq) => new(seq, "humans", "agent-one", "?", "question", Now);

        var waiting = FeedLogic.WaitingOnOperator([Question(9), Question(3), Question(5)], new HashSet<long> { 5 });

        Assert.Equal([3L, 9L], waiting.Select(message => message.Seq));
    }

    [Fact]
    public void RequireExistingTime_RefusesAnHourTheClocksSkip()
    {
        var springForward = TimeZoneInfo.TransitionTime.CreateFixedDateRule(new DateTime(1, 1, 1, 2, 0, 0), 3, 10);
        var fallBack = TimeZoneInfo.TransitionTime.CreateFixedDateRule(new DateTime(1, 1, 1, 2, 0, 0), 11, 3);
        var rule = TimeZoneInfo.AdjustmentRule.CreateAdjustmentRule(new DateTime(2000, 1, 1), new DateTime(2100, 1, 1), TimeSpan.FromHours(1), springForward, fallBack);
        var zone = TimeZoneInfo.CreateCustomTimeZone("Test", TimeSpan.FromHours(-5), "Test", "Test", "Test daylight", [rule]);

        FeedLogic.RequireExistingTime(new DateTime(2030, 3, 10, 1, 30, 0), zone);
        var error = Assert.Throws<InvalidOperationException>(() => FeedLogic.RequireExistingTime(new DateTime(2030, 3, 10, 2, 30, 0), zone));

        Assert.Contains("does not exist because of a daylight-saving transition", error.Message);
    }

    [Fact]
    public void ParseLocalBoundary_RejectsTextThatIsNotADate()
    {
        var error = Assert.Throws<InvalidOperationException>(() => FeedLogic.ParseLocalBoundary(" tomorrow ", isUpperBound: false));

        Assert.Equal("'tomorrow' is not a valid date. Use YYYY-MM-DD or YYYY-MM-DD HH:mm.", error.Message);
        Assert.Null(FeedLogic.ParseLocalBoundary("  ", isUpperBound: true));
    }

    [Theory]
    [InlineData(HumanMessageKind.Chat, "chat")]
    [InlineData(HumanMessageKind.Question, "question")]
    [InlineData(HumanMessageKind.Answer, "answer")]
    public void WireKind_NamesEveryKind(HumanMessageKind kind, string expected) =>
        Assert.Equal(expected, HumansLogic.WireKind(kind));

    [Fact]
    public void WireKind_RefusesAKindItCannotName() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => HumansLogic.WireKind((HumanMessageKind)42));

    [Fact]
    public void ClassifyFailure_AnErrorWithoutAMessageIsNamedByItsType()
    {
        var silent = HumansLogic.ClassifyFailure(new InvalidOperationException(" "));
        var spoken = HumansLogic.ClassifyFailure(new InvalidOperationException("Operator access is not configured."));
        var timedOut = HumansLogic.ClassifyFailure(new TaskCanceledException("timed out"));

        Assert.Equal(new PostFailure("InvalidOperationException", true, false), silent);
        Assert.Equal(new PostFailure("Operator access is not configured.", true, false), spoken);
        Assert.Equal(new PostFailure("Unable to reach StruggleBus: timed out", true, false), timedOut);
    }

    [Theory]
    [InlineData("block", "Block", true)]
    [InlineData("block-agent", "Block", true)]
    [InlineData("unblock", "Unblock", false)]
    [InlineData("retire", "Retire", true)]
    [InlineData("rotate", "Rotate secret", false)]
    [InlineData("revoke", "Revoke", true)]
    [InlineData("revoke-device", "Revoke", true)]
    [InlineData("Block", "Block", false)]
    [InlineData("hibernate", "hibernate", false)]
    public void AdminActions_HaveALabelAndADangerMark(string action, string label, bool danger)
    {
        var row = new AdminRow { Kind = AdminRowKind.Agent, Id = "a1", Name = "agent-one", State = "enabled" };

        var rowAction = new AdminRowAction(row, action, "effect");

        Assert.Equal(label, rowAction.Label);
        Assert.Equal(danger, rowAction.IsDanger);
        Assert.Same(row, rowAction.Row);
        Assert.Equal("effect", rowAction.Effect);
    }

    [Fact]
    public void AdminRows_DescribeDevicesThatLostAccessOrOnlyRead()
    {
        var revoked = AdminLogic.DeviceRow(new ManagedDevice("d1", "Old PC", "revoked", Now, false, false, []), Now);
        var current = AdminLogic.DeviceRow(new ManagedDevice("d2", "Ops PC", "enabled", Now, true, true, []), Now);

        Assert.Equal("no longer has access  ·  read only", revoked.Meta);
        Assert.Equal(string.Empty, revoked.Note);
        Assert.Equal("active now  ·  operator access saved", current.Meta);
        Assert.Equal("this PC", current.Note);
        Assert.True(current.IsThisDevice);
    }

    [Fact]
    public void AdminSummary_CountsBlockedAndInactiveRows()
    {
        AdminRow Row(string state) => new() { Kind = AdminRowKind.Agent, Id = state, Name = state, State = state };

        Assert.Equal("No agents.", AdminLogic.Summary([], "agent"));
        Assert.Equal("1 agent.", AdminLogic.Summary([Row("enabled")], "agent"));
        Assert.Equal("4 agents, 1 blocked, 2 no longer active.", AdminLogic.Summary([Row("enabled"), Row("blocked"), Row("retired"), Row("revoked")], "agent"));
    }

    [Fact]
    public void AdminFilter_WithNoTextKeepsEverythingBlockedFirst()
    {
        AdminRow Row(string name, string state) => new() { Kind = AdminRowKind.Agent, Id = name, Name = name, State = state };

        var rows = AdminLogic.Filter([Row("c", "retired"), Row("b", "enabled"), Row("a", "blocked")], null);

        Assert.Equal(["a", "b", "c"], rows.Select(row => row.Name));
    }

    [Theory]
    [InlineData(500, true)]
    [InlineData(429, true)]
    [InlineData(404, false)]
    public void IsTransient_DependsOnTheStatusForARefusal(int status, bool expected) =>
        Assert.Equal(expected, MonitorLogic.IsTransient(new BusApiException(status, "detail", "message")));

    [Fact]
    public void IsTransient_IsTrueForNetworkTroubleOnly()
    {
        Assert.True(MonitorLogic.IsTransient(new HttpRequestException("down")));
        Assert.True(MonitorLogic.IsTransient(new IOException("reset")));
        Assert.True(MonitorLogic.IsTransient(new TimeoutException()));
        Assert.True(MonitorLogic.IsTransient(new TaskCanceledException()));
        Assert.False(MonitorLogic.IsTransient(new InvalidOperationException("bug")));
    }

    [Fact]
    public void BusLogEntry_LabelsAndSummarisesALine()
    {
        var at = new DateTimeOffset(2030, 1, 1, 9, 5, 7, TimeSpan.Zero);
        var audit = new BusLogEntry(at, "audit", "error", "agent.blocked", "agent-one", "operator", 403, "10.0.0.5", "refused");
        var request = new BusLogEntry(at, "request", "info", "GET /status", null, " ", 200, null, "200 OK");
        var bare = new BusLogEntry(at, "server", "info", "started", null, null, null, null, "");

        Assert.Equal("AUDIT", audit.SourceLabel);
        Assert.Equal(at.ToLocalTime().ToString("ddd d MMM HH:mm:ss"), audit.TimeLabel);
        Assert.Equal("HTTP 403  ·  agent-one  ·  by operator  ·  from 10.0.0.5  ·  refused", audit.Summary);
        Assert.Equal("HTTP 200", request.Summary);
        Assert.Equal(string.Empty, bare.Summary);
        Assert.Equal(("Bad", true), (audit.Tone, audit.IsProblem));
        Assert.Equal(("Muted", false), (request.Tone, request.IsProblem));
        Assert.Contains("audit    error    agent.blocked  HTTP 403", audit.ToLine());
    }

    [Fact]
    public void ConnectionTracker_AMaintenanceNoticeIsReportedOnceAndExplainsTheOutage()
    {
        var tracker = new ConnectionTracker();
        var installAt = Now.AddMinutes(10);
        var notice = new BusMessage(1, "announce", "strugglebus", $"Strugglebus maintenance: release 0.2.70 is scheduled for installation at {installAt:O}. Expect a short outage.", "status", Now);

        var first = tracker.ReportMessage(notice, Now);
        var repeated = tracker.ReportMessage(notice, Now.AddMinutes(1));
        var stale = new ConnectionTracker().ReportMessage(notice, installAt.AddHours(2));
        var unrelated = tracker.ReportMessage(notice with { Body = "Strugglebus maintenance: release 0.2.70 is scheduled for installation at sometime. Soon." }, Now);
        tracker.ReportUp(Now);
        tracker.ReportDown(installAt, "connection refused");
        var back = tracker.ReportUp(installAt.AddSeconds(42));
        tracker.ReportDown(installAt.AddMinutes(5), "connection refused");
        var later = tracker.ReportUp(installAt.AddMinutes(6));

        Assert.Equal("Warn", first?.Tone);
        Assert.StartsWith("Maintenance announced: release 0.2.70 installs at ", first?.Text);
        Assert.Null(repeated);
        Assert.Null(stale);
        Assert.Null(unrelated);
        Assert.Equal("Reconnected after scheduled maintenance (release 0.2.70). Offline for 42s.", back?.Text);
        Assert.Equal("Reconnected. Offline for 1m 0s.", later?.Text);
    }

    [Fact]
    public void ConnectionTracker_ARestartIsNoticedByItsStartTimeOrVersion()
    {
        var tracker = new ConnectionTracker();
        var started = Now.AddHours(-3);

        Assert.Null(tracker.ReportBus("0.2.65", started, Now));
        Assert.Null(tracker.ReportBus("0.2.65", started, Now));
        Assert.Null(tracker.ReportBus("0.2.65", null, Now));
        Assert.Null(tracker.ReportBus("0.2.65", started, Now));
        Assert.Null(tracker.ReportBus("0.2.65", started.AddHours(-1), Now));
        var restarted = tracker.ReportBus("0.2.65", Now, Now);
        var upgraded = tracker.ReportBus("0.2.66", Now.AddMinutes(1), Now);

        Assert.Equal("Warn", restarted?.Tone);
        Assert.StartsWith("The bus restarted at ", restarted?.Text);
        Assert.Equal("The bus is now on version 0.2.66 (was 0.2.65).", upgraded?.Text);
    }

    [Fact]
    public void ConnectionLog_SkipsNullsAndImmediateRepeatsOnly()
    {
        var log = ConnectionLog.LoadFromPath(null);
        var first = new ConnectionEvent(Now, "Bad", "Bus not reachable.");

        Assert.False(log.Add(null));
        Assert.True(log.Add(first));
        Assert.False(log.Add(first with { At = Now.AddSeconds(30) }));
        Assert.True(log.Add(first with { At = Now.AddMinutes(5) }));
        Assert.True(log.Add(new ConnectionEvent(Now.AddMinutes(5), "Ok", "Reconnected.")));

        Assert.Equal(3, log.Events.Count);
        Assert.Equal(first.At.ToLocalTime().ToString("ddd d MMM HH:mm:ss"), first.TimeLabel);
    }

    [Fact]
    public void SavingToAPlaceThatCannotBeWrittenIsNotAnError()
    {
        var blocker = Path.Combine(TempFiles.NewDirectory(), "not-a-folder");
        File.WriteAllText(blocker, "a file where a folder is needed");

        new AppSettings { AutoUpdate = false }.SaveToPath(Path.Combine(blocker, "settings.json"));
        var log = ConnectionLog.LoadFromPath(Path.Combine(blocker, "connection-log.json"));

        Assert.True(log.Add(new ConnectionEvent(Now, "Ok", "Connected to the bus.")));
        Assert.Single(log.Events);
        Assert.Equal("a file where a folder is needed", File.ReadAllText(blocker));
        Assert.True(AppSettings.LoadFromPath(Path.Combine(blocker, "settings.json")).AutoUpdate);
    }

    [Fact]
    public void Models_CarryWhatTheBusSent()
    {
        var payload = new EnrollmentPayload("https://bus.test", "der", "sha", "Ops PC", "token", Now, 1);
        var snapshot = new Snapshot([new BusMessage(1, "ops", "agent-one", "hi", "status", Now)], [], "normal", 1);
        var confirmation = new Confirmation("c-1", "block-agent", "a1", "agent-one", "Blocks it");
        var action = new ActionResult(true, "Done.", "agent-one");
        var enrollment = new EnrollmentResult("Title", "Detail", null);
        var refusal = new BusApiException(409, "Conflict detail", "Conflict message");

        Assert.Equal("Ops PC", payload.DeviceLabel);
        Assert.Equal("hi", Assert.Single(snapshot.Messages).Body);
        Assert.Equal(("c-1", "block-agent", "a1", "agent-one", "Blocks it"), (confirmation.Id, confirmation.Action, confirmation.TargetId, confirmation.TargetLabel, confirmation.Effect));
        Assert.Equal((true, "Done.", "agent-one"), (action.Applied, action.Detail, action.TargetLabel));
        Assert.Equal(("Title", "Detail", null), (enrollment.Title, enrollment.Detail, enrollment.Secret));
        Assert.Equal((409, "Conflict detail", "Conflict message"), (refusal.StatusCode, refusal.Detail, refusal.Message));
    }
}
