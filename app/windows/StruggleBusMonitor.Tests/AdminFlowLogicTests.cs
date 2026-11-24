namespace StruggleBusMonitor.Tests;

public class AdminFlowLogicTests
{
    private static readonly DateTimeOffset Noon = new(new DateTime(2026, 11, 17, 12, 0, 0, DateTimeKind.Local));

    private static AdminRow Row(AdminRowKind kind, string state = "enabled", bool legacy = false, string name = "prox-manager") =>
        new AdminRow { Kind = kind, Id = "id-1", Name = name, State = state, Legacy = legacy, Version = 3 }
            .WithActions([new AdminActionOption("block", "Blocks it at once.")]);

    private static BusMessage Message(long seq, DateTimeOffset at) => new(seq, "general", "prox-manager", "body", "chat", at);

    private static string Refused(Action act) => Assert.Throws<InvalidOperationException>(act).Message;

    // ---- Lists -------------------------------------------------------------------------------

    [Theory]
    [InlineData(404, true)]
    [InlineData(405, true)]
    [InlineData(403, false)]
    [InlineData(500, false)]
    public void ABusWithoutManagementListsIsRecognisedByItsAnswer(int status, bool legacy)
    {
        Assert.Equal(legacy, AdminFlow.IsLegacyBus(new BusApiException(status, "x", "x")));
    }

    [Fact]
    public void TheAgentsSummaryCountsOrSaysHowManyMatch()
    {
        var all = new[] { Row(AdminRowKind.Agent), Row(AdminRowKind.Agent, "blocked") };

        Assert.Equal("2 agents, 1 blocked.", AdminFlow.AgentsSummary(false, 2, all));
        Assert.Equal("1 of 2 agents match.", AdminFlow.AgentsSummary(false, 1, all));
        Assert.Equal(AdminFlow.LegacyAgents, AdminFlow.AgentsSummary(true, 2, all));
    }

    [Fact]
    public void TheDeviceAndServicePrincipalSummariesExplainAnOlderBus()
    {
        var one = new[] { Row(AdminRowKind.Device) };

        Assert.Equal("1 device.", AdminFlow.DevicesSummary(false, one));
        Assert.Equal(AdminFlow.LegacyLists, AdminFlow.DevicesSummary(true, one));
        Assert.Equal("1 service principal.", AdminFlow.ServicePrincipalsSummary(false, one));
        Assert.Equal("No service principals. Create one on the Enroll tab.", AdminFlow.ServicePrincipalsSummary(false, []));
        Assert.Equal(AdminFlow.LegacyLists, AdminFlow.ServicePrincipalsSummary(true, []));
    }

    // ---- Row actions -------------------------------------------------------------------------

    [Fact]
    public void DevicesAndLegacyAgentsUseTheServerConfirmedFlow()
    {
        Assert.Equal(OperatorAction.RevokeDevice, AdminFlow.ConfirmedAction(Row(AdminRowKind.Device)));
        Assert.Equal(OperatorAction.RevokeDevice, AdminFlow.ConfirmedAction(Row(AdminRowKind.Device, legacy: true)));
        Assert.Equal(OperatorAction.BlockAgent, AdminFlow.ConfirmedAction(Row(AdminRowKind.Agent, legacy: true)));
        Assert.Null(AdminFlow.ConfirmedAction(Row(AdminRowKind.Agent)));
        Assert.Null(AdminFlow.ConfirmedAction(Row(AdminRowKind.ServicePrincipal)));
    }

    [Fact]
    public void ADirectActionNeedsAReasonThenTheOperatorGrant()
    {
        Assert.Equal("Enter an audit reason before requesting an action.", Refused(() => AdminFlow.RequireControl("   ", hasGrant: false)));
        Assert.Equal("Save operator access on the Access tab first.", Refused(() => AdminFlow.RequireControl("cleanup", hasGrant: false)));
        Assert.Equal("cleanup", AdminFlow.RequireControl("  cleanup ", hasGrant: true));
    }

    [Fact]
    public void AContainmentActionNeedsAReason()
    {
        Assert.Equal("Enter an audit reason before requesting an action.", Refused(() => AdminFlow.RequireReason(" ")));
        AdminFlow.RequireReason("incident 12");
    }

    [Fact]
    public void TheReviewAndHelloPromptsNameTheTargetActionAndEffect()
    {
        var agent = Row(AdminRowKind.Agent).Actions[0];
        var principal = Row(AdminRowKind.ServicePrincipal, name: "nightly-audit").Actions[0];

        Assert.Equal("TARGET\nagent prox-manager\n\nACTION\nBlock\n\nEFFECT\nBlocks it at once.\n\nContinue to Windows Hello?", AdminFlow.ControlReview(agent));
        Assert.Equal("Block agent prox-manager", AdminFlow.ControlHelloPrompt(agent));
        Assert.Equal("Block service principal nightly-audit", AdminFlow.ControlHelloPrompt(principal));
        Assert.Equal(
            "TARGET\ndesk-pc\n\nEFFECT\nRevokes it.\n\nContinue to Windows Hello?",
            AdminFlow.ContainmentReview(new Confirmation("c1", "revoke-device", "d1", "desk-pc", "Revokes it.")));
    }

    [Fact]
    public void ResultsAreWordedForTheOperator()
    {
        Assert.Equal("prox-manager: blocked.", AdminFlow.ControlResultText(new ControlResult(true, "blocked.", "prox-manager", "blocked", null)));
        Assert.Equal("prox-manager changed before this ran, so nothing was done. The list has been reloaded.", AdminFlow.ControlConflict(Row(AdminRowKind.Agent)));
        Assert.Equal("Applied: frozen.", AdminFlow.ActionResultText(new ActionResult(true, "frozen.", "global")));
        Assert.Equal("Not applied: already frozen.", AdminFlow.ActionResultText(new ActionResult(false, "already frozen.", "global")));
    }

    [Fact]
    public void OnlyAnAppliedRevocationOfThisVeryDeviceForgetsThePc()
    {
        var session = new Session("https://bus", "c", [], "d1", "desk-pc");
        var applied = new ActionResult(true, "ok", "desk-pc");
        var refused = new ActionResult(false, "no", "desk-pc");

        Assert.True(AdminFlow.RevokedThisPc(OperatorAction.RevokeDevice, applied, "d1", session));
        Assert.False(AdminFlow.RevokedThisPc(OperatorAction.RevokeDevice, refused, "d1", session));
        Assert.False(AdminFlow.RevokedThisPc(OperatorAction.RevokeDevice, applied, "d2", session));
        Assert.False(AdminFlow.RevokedThisPc(OperatorAction.BlockAgent, applied, "d1", session));
        Assert.False(AdminFlow.RevokedThisPc(OperatorAction.RevokeDevice, applied, "d1", null));
    }

    // ---- Enrollment --------------------------------------------------------------------------

    [Fact]
    public void TheSelectedEnrollmentKindFollowsTheRadioButtons()
    {
        Assert.Equal(EnrollmentKind.Agent, AdminFlow.KindOf(servicePrincipal: false, device: false));
        Assert.Equal(EnrollmentKind.ServicePrincipal, AdminFlow.KindOf(servicePrincipal: true, device: false));
        Assert.Equal(EnrollmentKind.Device, AdminFlow.KindOf(servicePrincipal: false, device: true));
    }

    [Fact]
    public void TheEnrollmentFormChangesWithTheKind()
    {
        var agent = AdminFlow.Form(EnrollmentKind.Agent);
        var principal = AdminFlow.Form(EnrollmentKind.ServicePrincipal);
        var device = AdminFlow.Form(EnrollmentKind.Device);

        Assert.Equal(("Agent name", true, "Description (optional)", false, "Create onboarding package"),
            (agent.NameLabel, agent.ShowSecond, agent.SecondLabel, agent.MonoSecond, agent.CreateLabel));
        Assert.Contains("for example adlab-cli-win", agent.Hint);
        Assert.Equal(("Service principal name", true, "Agent name prefix", true, "Create service principal"),
            (principal.NameLabel, principal.ShowSecond, principal.SecondLabel, principal.MonoSecond, principal.CreateLabel));
        Assert.Contains("expire within 12 hours", principal.Hint);
        Assert.Equal(("Device label", false, "Create device enrollment"), (device.NameLabel, device.ShowSecond, device.CreateLabel));
        Assert.Contains("another phone or PC", device.Hint);
    }

    [Fact]
    public void EnrollmentInputsAreCheckedInOrder()
    {
        Assert.Equal("Enter the agent name.", Refused(() => AdminFlow.RequireEnrollment(EnrollmentKind.Agent, "", "", "", false)));
        Assert.Equal("Enter the device label.", Refused(() => AdminFlow.RequireEnrollment(EnrollmentKind.Device, "", "", "", false)));
        Assert.Equal("Enter the service principal name.", Refused(() => AdminFlow.RequireEnrollment(EnrollmentKind.ServicePrincipal, "", "", "", false)));
        Assert.Equal("Enter the agent name prefix its workers will use.",
            Refused(() => AdminFlow.RequireEnrollment(EnrollmentKind.ServicePrincipal, "nightly-audit", "", "", false)));
        Assert.Equal("Enter an audit reason.", Refused(() => AdminFlow.RequireEnrollment(EnrollmentKind.Agent, "new-agent", "", "", false)));
        Assert.Equal("Save operator access above before creating enrollments.",
            Refused(() => AdminFlow.RequireEnrollment(EnrollmentKind.Agent, "new-agent", "", "setup", false)));

        Assert.Equal("Agent names need at least one hyphen, joining a project and a platform, for example adlab-cli-win.",
            Refused(() => AdminFlow.RequireEnrollment(EnrollmentKind.Agent, "newagent", "", "setup", true)));
        Assert.Equal("Device labels can only use lowercase letters, digits and hyphens. Remove: !",
            Refused(() => AdminFlow.RequireEnrollment(EnrollmentKind.Device, "laptop!", "", "setup", true)));
        Assert.Equal("Agent name prefixes can only use lowercase letters, digits and hyphens. Remove: space",
            Refused(() => AdminFlow.RequireEnrollment(EnrollmentKind.ServicePrincipal, "nightly-audit", "audit worker", "setup", true)));

        AdminFlow.RequireEnrollment(EnrollmentKind.Agent, "new-agent", "", "setup", true);
        AdminFlow.RequireEnrollment(EnrollmentKind.ServicePrincipal, "nightly-audit", "audit-worker", "setup", true);
    }

    [Fact]
    public void EnrollmentNamesAreSentAsTheBusStoresThem()
    {
        Assert.Equal("build-agent", AdminFlow.EnrollmentName(EnrollmentKind.Agent, "Build Agent"));
        Assert.Equal("audit-worker", AdminFlow.EnrollmentSecond(EnrollmentKind.ServicePrincipal, " Audit-Worker "));
        Assert.Equal("Runs the Nightly build", AdminFlow.EnrollmentSecond(EnrollmentKind.Agent, "Runs the Nightly build"));
        Assert.Equal(new NameFeedback("Will be created as build-agent", false), AdminFlow.NameFeedback(EnrollmentKind.Agent, "Build Agent"));
        Assert.True(AdminFlow.SecondFeedback(EnrollmentKind.ServicePrincipal, "audit worker").IsProblem);
        Assert.Equal(NameFeedback.None, AdminFlow.SecondFeedback(EnrollmentKind.Agent, "Any description at all!"));
    }

    [Theory]
    [InlineData(EnrollmentKind.Agent, "Create an enrollment for agent new-one")]
    [InlineData(EnrollmentKind.ServicePrincipal, "Create an enrollment for service principal new-one")]
    [InlineData(EnrollmentKind.Device, "Create an enrollment for device new-one")]
    public void TheEnrollmentHelloPromptSaysWhatIsBeingCreated(EnrollmentKind kind, string expected)
    {
        Assert.Equal(expected, AdminFlow.EnrollmentHelloPrompt(kind, "new-one"));
    }

    // ---- Export ------------------------------------------------------------------------------

    [Fact]
    public void ExportNamesAndBoundariesAreFormattedInvariantly()
    {
        Assert.Equal("2026-11-17 12:00", AdminFlow.ExportBoundary(Noon));
        Assert.Equal("strugglebus-messages-20261117-120509.csv", AdminFlow.ExportFileName(new DateTime(2026, 11, 17, 12, 5, 9)));
        Assert.Equal("Saved out.csv with 3 messages.", AdminFlow.ExportSaved("out.csv", 3));
    }

    [Fact]
    public void TheExportWindowMayBeOpenEndedButNotBackwards()
    {
        Assert.Equal(((DateTimeOffset?)null, (DateTimeOffset?)null), AdminFlow.ExportWindow("", " "));
        Assert.Equal(((DateTimeOffset?)Noon, (DateTimeOffset?)null), AdminFlow.ExportWindow("2026-11-17 12:00", ""));
        var (from, to) = AdminFlow.ExportWindow("2026-11-17", "2026-11-17");
        Assert.True(from < to);
        Assert.Equal("The export start must be earlier than the end.", Refused(() => AdminFlow.ExportWindow("2026-11-18", "2026-11-17")));
        Assert.Contains("is not a valid date", Refused(() => AdminFlow.ExportWindow("yesterday", "")));
    }

    [Fact]
    public void TheExportKeepsMessagesInsideTheWindowOldestFirst()
    {
        var messages = new[] { Message(3, Noon.AddHours(2)), Message(1, Noon.AddHours(-2)), Message(2, Noon) };

        Assert.Equal([1, 2, 3], AdminFlow.SelectExport(messages, null, null).Select(message => message.Seq));
        Assert.Equal([2, 3], AdminFlow.SelectExport(messages, Noon, null).Select(message => message.Seq));
        Assert.Equal([1, 2], AdminFlow.SelectExport(messages, null, Noon).Select(message => message.Seq));
        Assert.Equal([2], AdminFlow.SelectExport(messages, Noon.AddMinutes(-1), Noon.AddMinutes(1)).Select(message => message.Seq));
        Assert.Equal("No retained messages fall inside those dates.", Refused(() => AdminFlow.SelectExport(messages, Noon.AddDays(1), null)));
    }

    [Theory]
    [InlineData("=SUM(A1)", true)]
    [InlineData("+1", true)]
    [InlineData("-1", true)]
    [InlineData("@cmd", true)]
    [InlineData("   =SUM(A1)", true)]
    [InlineData("\t=SUM(A1)", true)]
    [InlineData("\r@cmd", true)]
    [InlineData("plain text", false)]
    [InlineData("\tindented text", false)]
    [InlineData("a=b", false)]
    [InlineData("   ", false)]
    [InlineData("", false)]
    public void ACellASpreadsheetWouldRunAsAFormulaIsQuotedAndFlagged(string body, bool sanitized)
    {
        var row = MainWindow.BuildCsv([new BusMessage(1, "general", "prox-manager", body, "chat", Noon)])
            .Split(Environment.NewLine)[1];

        Assert.EndsWith(sanitized ? ",true" : ",false", row);
        Assert.Equal(sanitized, row.Contains(",'" + body.Replace("\"", "\"\"")) || row.Contains(",\"'" + body));
    }
}

public class SettingsLogicTests
{
    private static readonly DateTime At = new(2026, 11, 17, 9, 5, 7);

    [Fact]
    public void TheThemeModeFollowsTheChoice()
    {
        Assert.Equal(AppThemeMode.Light, SettingsLogic.ModeFor(light: true, system: false));
        Assert.Equal(AppThemeMode.System, SettingsLogic.ModeFor(light: false, system: true));
        Assert.Equal(AppThemeMode.Dark, SettingsLogic.ModeFor(light: false, system: false));
    }

    [Fact]
    public void ACopyThatWasNotInstalledCannotCheckForUpdates()
    {
        Assert.Equal(UpdateState.UpToDate, SettingsLogic.InitialStatus(canUpdate: true).State);
        var view = SettingsLogic.View(SettingsLogic.InitialStatus(canUpdate: false), false, true, At);

        Assert.False(view.CanCheck);
        Assert.False(view.ShowAction);
        Assert.False(view.ShowTitleBarButton);
        Assert.Equal(SettingsLogic.NotInstalledText, view.Text);
    }

    [Fact]
    public void ADownloadInProgressCannotBeStartedAgain()
    {
        var view = SettingsLogic.View(new UpdateStatus(UpdateState.Downloading, "1.9.0"), true, true, At);

        Assert.False(view.CanCheck);
    }

    [Fact]
    public void AnAvailableUpdateOffersTheDownload()
    {
        var view = SettingsLogic.View(new UpdateStatus(UpdateState.Available, "1.9.0"), true, false, At);

        Assert.True(view.ShowAction);
        Assert.Equal("Download version 1.9.0", view.ActionLabel);
        Assert.False(view.ShowTitleBarButton);
        Assert.True(view.CanCheck);
        Assert.Equal("Version 1.9.0 is available. Download it, then restart to install it.", view.Text);
    }

    [Fact]
    public void ADownloadedUpdateOffersTheRestartInBothPlaces()
    {
        var automatic = SettingsLogic.View(new UpdateStatus(UpdateState.ReadyToRestart, "1.9.0"), false, true, At);
        var manual = SettingsLogic.View(new UpdateStatus(UpdateState.ReadyToRestart, "1.9.0"), false, false, At);

        Assert.True(automatic.ShowAction);
        Assert.Equal("Restart to update", automatic.ActionLabel);
        Assert.True(automatic.ShowTitleBarButton);
        Assert.Equal("Update 1.9.0 ready · Restart", automatic.TitleBarLabel);
        Assert.Equal("Version 1.9.0 is downloaded. It installs when you restart, or the next time you close the app.", automatic.Text);
        Assert.Equal("Version 1.9.0 is downloaded. It installs when you press Restart to update.", manual.Text);
    }

    [Fact]
    public void TheOtherStatesOnlyChangeTheText()
    {
        static string Text(UpdateStatus status, bool checkedNow, bool auto) => SettingsLogic.StatusText(status, checkedNow, auto, At);

        Assert.Equal("Downloading version 1.9.0…", Text(new UpdateStatus(UpdateState.Downloading, "1.9.0"), false, true));
        Assert.Equal("The update check failed: no network", Text(new UpdateStatus(UpdateState.Failed, Detail: "no network"), true, true));
        Assert.Equal("The last automatic update check failed. It will be tried again.", Text(new UpdateStatus(UpdateState.Failed, Detail: "no network"), false, true));
        Assert.Equal("You are on the latest version. Checked 09:05.", Text(new UpdateStatus(UpdateState.UpToDate), true, false));
        Assert.Equal("Updates are checked at startup and every few hours, then downloaded in the background.", Text(new UpdateStatus(UpdateState.UpToDate), false, true));
        Assert.Equal("Automatic updates are off. Nothing is checked, downloaded or installed until you press Check for updates.", Text(new UpdateStatus(UpdateState.UpToDate), false, false));
        Assert.False(SettingsLogic.View(new UpdateStatus(UpdateState.Downloading, "1.9.0"), false, true, At).ShowAction);
    }

    [Fact]
    public void TheBusLogStatusNamesTheVersionAndWhenItStarted()
    {
        var started = new DateTimeOffset(new DateTime(2026, 11, 16, 22, 30, 0, DateTimeKind.Local));

        Assert.Equal("StruggleBus 0.2.65. Loaded 09:05:07.", SettingsLogic.BusLogStatus(new BusLog("0.2.65", null, []), At));
        Assert.Equal($"StruggleBus 0.2.65, running since {started:ddd d MMM} 22:30. Loaded 09:05:07.", SettingsLogic.BusLogStatus(new BusLog("0.2.65", started, []), At));
    }

    [Fact]
    public void AnEmptyBusLogListSaysWhy()
    {
        var entry = new BusLogEntry(DateTimeOffset.UnixEpoch, "audit", "info", "agent.block", null, null, null, null, "");

        Assert.Equal("Enroll this PC to read the bus log.", SettingsLogic.BusLogEmptyText(false, null));
        Assert.Equal("Nothing loaded.", SettingsLogic.BusLogEmptyText(true, null));
        Assert.Equal("The bus has nothing logged.", SettingsLogic.BusLogEmptyText(true, new BusLog("1", null, [])));
        Assert.Equal("Nothing matches.", SettingsLogic.BusLogEmptyText(true, new BusLog("1", null, [entry])));
    }

    [Fact]
    public void AMaintenanceNoticeIsOnlyNewWhenItsTextIsNotLoggedYet()
    {
        var known = new[] { new ConnectionEvent(DateTimeOffset.UnixEpoch, "Warn", "Maintenance announced.") };

        Assert.False(SettingsLogic.IsNewNotice(null, known));
        Assert.False(SettingsLogic.IsNewNotice(new ConnectionEvent(DateTimeOffset.UtcNow, "Warn", "Maintenance announced."), known));
        Assert.True(SettingsLogic.IsNewNotice(new ConnectionEvent(DateTimeOffset.UtcNow, "Warn", "Another one."), known));
    }
}
