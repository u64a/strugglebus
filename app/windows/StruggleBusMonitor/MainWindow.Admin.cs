using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace StruggleBusMonitor;

/// <summary>Admin page: the operator console. Agents, devices, service principals, enrollment, access and export.</summary>
public partial class MainWindow
{
    private readonly ObservableCollection<AdminRow> _adminAgents = [];
    private readonly ObservableCollection<AdminRow> _adminDevices = [];
    private readonly ObservableCollection<AdminRow> _adminServicePrincipals = [];
    private readonly ObservableCollection<HostRow> _adminHosts = [];
    private bool _adminHostsLoaded;
    private List<AdminRow> _adminAgentRows = [];

    /// <summary>True when the bus is too old to list managed targets, so rows come from the live roster.</summary>
    private bool _adminLegacy;
    private bool _adminLoaded;
    private DateTimeOffset? _adminLoadedAt;
    private IReadOnlyList<AdminRow> _adminAgentMatches = [];
    private int _adminAgentsShowing = AdminFlow.AgentPageSize;

    private void InitializeAdmin()
    {
        AdminAgentList.ItemsSource = _adminAgents;
        AdminDeviceList.ItemsSource = _adminDevices;
        AdminSpnList.ItemsSource = _adminServicePrincipals;
        AdminHostList.ItemsSource = _adminHosts;
        HostSigners.Text = SiteSignersStore.Load();
        ShowEarlierSigners();
        SignersSummary.Text = SiteSignersLogic.Summary(HostSigners.Text);
        SignersList.ItemsSource = FleetPublishLogic.Signers(HostSigners.Text);
        HostRemotes.Text = _settings.HostRemotes;
        HostFleetGit.IsChecked = _settings.HostFleetSource == "git";
        HostFleetEither.IsChecked = _settings.HostFleetSource == "either";
        UpdateEnrollmentForm();
        SetExportWindow(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now);
        ShowAdminTab();
    }

    /// <summary>
    /// Opens with the lists it already has, and fetches them again only when they are older
    /// than a minute. Fetching every time made the page slow to open on a busy bus.
    /// </summary>
    private void OnAdminPageShown()
    {
        UpdateGrantStatus();
        if (AdminFlow.ListsAreStale(_adminLoadedAt, DateTimeOffset.Now)) _ = RunBusy(LoadAdminListsAsync);
    }

    private void AdminTab_Checked(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        ShowAdminTab();
        if (!_adminLoaded) _ = RunBusy(LoadAdminListsAsync);
        if (AdminTabHosts.IsChecked == true && !_adminHostsLoaded) _ = RunBusy(LoadHostsAsync);
    }

    internal async void AdminHostsReload_Click(object sender, RoutedEventArgs e) => await RunBusy(LoadHostsAsync, sender);

    // ---- Add a host ---------------------------------------------------------------------------

    private void HostName_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_ready) ShowNameFeedback(HostNameFeedback, AddHostLogic.NameFeedback(HostName.Text));
    }

    private string SelectedFleetSource
    {
        get
        {
            if (HostFleetGit.IsChecked == true) return "git";
            return HostFleetEither.IsChecked == true ? "either" : AddHostLogic.DefaultFleetSource;
        }
    }

    private AddHostForm ReadAddHostForm() => new(
        HostName.Text, HostEngineClaude.IsChecked == true, HostEngineCopilot.IsChecked == true,
        HostDedicated.IsChecked == true, HostSigners.Text, HostRemotes.Text, SelectedFleetSource, HostReason.Text.Trim());

    internal async void HostCreate_Click(object sender, RoutedEventArgs e) => await RunBusy(CreateHostFileAsync, sender);

    /// <summary>
    /// Checks everything first, asks where to save, then Windows Hello, and only then asks the bus
    /// for the code: a code works once, so it is not spent on a form that would be refused or a
    /// save the operator cancels.
    /// </summary>
    private async Task CreateHostFileAsync()
    {
        if (_api.Session is not { } session) return;
        var form = ReadAddHostForm();
        var now = DateTimeOffset.Now;
        if (AddHostLogic.Problem(form, session, _api.HasOperatorGrant(), now) is { } problem) throw new InvalidOperationException(problem);
        var prefix = AddHostLogic.Prefix(form.PcName);
        if (_platform.PickHostFilePath(this, HostEnrolFile.FileName) is not { } path) return;
        await RequireHelloAsync(AddHostLogic.HelloPrompt(prefix));

        var code = await MintHostCodeAsync(prefix, form.Reason);
        var data = AddHostLogic.Data(form, session, code.Code ?? string.Empty, now);
        var file = await WriteHostFileAsync(path, data);
        var installer = await WriteInstallerBesideAsync(path);
        RememberSiteSettings(form);
        HostResult.Text = AddHostLogic.ResultText(Path.GetFileName(path), data, file, installer, code.ExpiresAt, now);
        HostResultPanel.Visibility = Visibility.Visible;
        HostName.Clear();
        HostReason.Clear();
    }

    /// <summary>Writes the file only if the installer would accept it, now that it holds the real code.</summary>
    private static async Task<byte[]> WriteHostFileAsync(string path, HostEnrolData data)
    {
        if (HostEnrolFile.Problem(data) is { } refused) throw new InvalidOperationException(refused);
        var file = HostEnrolFile.Render(data);
        await File.WriteAllBytesAsync(path, file);
        return file;
    }

    /// <summary>
    /// Saves the installer next to the data file, unchanged, so the two travel together: the
    /// signed copy that came with the app when it passes its check, the built-in one otherwise.
    /// </summary>
    private async Task<HostInstaller> WriteInstallerBesideAsync(string dataFilePath)
    {
        var installer = HostInstallerLogic.Pick(AddHostLogic.Bootstrap(), _platform.SignedInstallerPath, Authenticode.Read);
        await File.WriteAllBytesAsync(Path.Combine(Path.GetDirectoryName(dataFilePath)!, AddHostLogic.BootstrapFileName), installer.Bytes);
        return installer;
    }

    private void RememberSiteSettings(AddHostForm form)
    {
        SiteSignersStore.Save(form.Signers);
        _settings.HostRemotes = form.Remotes;
        _settings.HostFleetSource = form.FleetSource;
        _settings.Save();
    }

    private async Task<HostCode> MintHostCodeAsync(string prefix, string reason)
    {
        try
        {
            return await _api.CreateHostEnrollmentAsync(Guid.NewGuid().ToString("D"), prefix, reason, CancellationToken.None);
        }
        catch (BusApiException error) when (AdminFlow.IsLegacyBus(error))
        {
            throw new InvalidOperationException(AddHostLogic.BusTooOld);
        }
    }

    /// <summary>Where each host's service principal came from. An older bus has no such list, and no host codes.</summary>
    private async Task<List<ManagedServicePrincipal>> HostPrincipalsAsync()
    {
        try
        {
            return await _api.GetManagedServicePrincipalsAsync(CancellationToken.None);
        }
        catch (BusApiException error) when (AdminFlow.IsLegacyBus(error))
        {
            return [];
        }
    }

    /// <summary>The agents the bus has marked as worker hosts, or null from a bus too old to mark any.</summary>
    private async Task<HashSet<string>?> MarkedHostsAsync()
    {
        try
        {
            var status = await _api.GetHostsStatusAsync(whole: false, CancellationToken.None);
            return status.Hosts.Select(host => host.AgentId).ToHashSet(StringComparer.Ordinal);
        }
        catch (BusApiException error) when (AdminFlow.IsLegacyBus(error))
        {
            return null;
        }
    }

    internal async void HostMark_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is HostRow row) await RunBusy(() => MarkHostAsync(row), sender);
    }

    /// <summary>
    /// Marks an agent as a worker host or takes the mark away: the operator grant first, then the
    /// review dialog, then Windows Hello, and only then the request.
    /// </summary>
    private async Task MarkHostAsync(HostRow row)
    {
        var mark = row.Marked != true;
        if (!_api.HasOperatorGrant()) throw new InvalidOperationException(AdminFlow.GrantNeeded);
        if (!_platform.Confirm(this, HostsPageLogic.MarkReview(row.AgentName, mark), "Review operator action")) return;
        await RequireHelloAsync(HostsPageLogic.MarkHelloPrompt(row.AgentName, mark));

        var result = await _api.MarkHostAsync(row.AgentId, row.AgentName, mark, HostsPageLogic.MarkReason(mark), CancellationToken.None);
        ShowAdminResult(AdminFlow.ControlResultText(result));
        _hostsLoadedAt = null;
        await LoadHostsAsync();
    }

    /// <summary>
    /// Worker hosts are the agents named "...-host". Whether each answers comes from the bus's own
    /// last-seen time; the rest comes from the newest status that host posted about itself.
    /// </summary>
    private async Task LoadHostsAsync()
    {
        if (_api.Session is null) return;
        var agents = await _api.GetAgentsAsync(CancellationToken.None);
        var principals = await HostPrincipalsAsync();
        var marked = await MarkedHostsAsync();
        var now = DateTimeOffset.Now;
        var rows = new List<HostRow>();
        foreach (var agent in HostsLogic.HostAgents(agents))
        {
            var recent = await _api.GetHistoryAsync(null, agent.Name, null, HostsLogic.StatusLookback, CancellationToken.None);
            rows.Add(HostsLogic.Row(agent, HostsLogic.Latest(recent, agent.Name), now, HostsLogic.PrincipalFor(agent, principals), marked?.Contains(agent.Id)));
        }
        _adminHostsLoaded = true;
        _adminHosts.Clear();
        foreach (var row in rows) _adminHosts.Add(row);
        AdminHostsSummary.Text = HostsLogic.Summary(rows);
    }

    private void ShowAdminTab()
    {
        AdminAgentsPanel.Visibility = VisibleWhen(AdminTabAgents.IsChecked == true);
        AdminDevicesPanel.Visibility = VisibleWhen(AdminTabDevices.IsChecked == true);
        AdminSpnPanel.Visibility = VisibleWhen(AdminTabSpn.IsChecked == true);
        AdminHostsPanel.Visibility = VisibleWhen(AdminTabHosts.IsChecked == true);
        AdminAddHostPanel.Visibility = VisibleWhen(AdminTabHosts.IsChecked == true);
        AdminFleetPanel.Visibility = VisibleWhen(AdminTabHosts.IsChecked == true);
        AdminEnrollPanel.Visibility = VisibleWhen(AdminTabEnroll.IsChecked == true);
        AdminAccessPanel.Visibility = VisibleWhen(AdminTabAccess.IsChecked == true);
        AdminExportPanel.Visibility = VisibleWhen(AdminTabExport.IsChecked == true);
        // Enrollment and export carry their own inputs; everything else shares one audit reason.
        AdminReasonCard.Visibility = VisibleWhen(
            AdminTabEnroll.IsChecked != true && AdminTabExport.IsChecked != true && AdminTabHosts.IsChecked != true);
    }

    internal async void AdminReload_Click(object sender, RoutedEventArgs e) => await RunBusy(LoadAdminListsAsync, sender);

    private void AdminShowRetired_Changed(object sender, RoutedEventArgs e)
    {
        if (_ready) _ = RunBusy(LoadAdminListsAsync);
    }

    private void AdminAgentFilter_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready) return;
        _adminAgentsShowing = AdminFlow.AgentPageSize;
        ApplyAdminAgentFilter();
    }

    internal void AdminAgentsMore_Click(object sender, RoutedEventArgs e)
    {
        _adminAgentsShowing += AdminFlow.AgentPageSize;
        ShowAdminAgentPage();
    }

    private async Task LoadAdminListsAsync()
    {
        if (_api.Session is not { } session) return;
        var now = DateTimeOffset.Now;
        List<AdminRow> devices;
        List<AdminRow> principals;
        try
        {
            var agents = await _api.GetManagedAgentsAsync(AdminShowRetired.IsChecked == true, CancellationToken.None);
            devices = (await _api.GetManagedDevicesAsync(CancellationToken.None)).Select(device => AdminLogic.DeviceRow(device, now)).ToList();
            principals = (await _api.GetManagedServicePrincipalsAsync(CancellationToken.None)).Select(AdminLogic.ServicePrincipalRow).ToList();
            _adminAgentRows = agents.Select(agent => AdminLogic.AgentRow(agent, now)).ToList();
            _adminLegacy = false;
        }
        catch (BusApiException error) when (AdminFlow.IsLegacyBus(error))
        {
            // A bus older than 0.2.64 has no management lists. Keep what it can do: block and self-revoke.
            _adminLegacy = true;
            _adminAgentRows = _agentModels.Select(agent => AdminLogic.LegacyAgentRow(agent, now)).ToList();
            devices = [AdminLogic.LegacyDeviceRow(session)];
            principals = [];
        }
        _adminLoaded = true;
        _adminLoadedAt = DateTimeOffset.Now;

        Replace(_adminDevices, AdminLogic.Filter(devices, null));
        Replace(_adminServicePrincipals, AdminLogic.Filter(principals, null));
        ApplyAdminAgentFilter();

        AdminShowRetired.Visibility = VisibleWhen(!_adminLegacy);
        AdminDevicesSummary.Text = AdminFlow.DevicesSummary(_adminLegacy, devices);
        AdminSpnSummary.Text = AdminFlow.ServicePrincipalsSummary(_adminLegacy, principals);
    }

    private void ApplyAdminAgentFilter()
    {
        _adminAgentMatches = AdminLogic.Filter(_adminAgentRows, AdminAgentFilter.Text);
        AdminAgentsSummary.Text = AdminFlow.AgentsSummary(_adminLegacy, _adminAgentMatches.Count, _adminAgentRows);
        ShowAdminAgentPage();
    }

    /// <summary>
    /// Puts only the first rows on screen. A row is a real control with its buttons, so a bus with
    /// hundreds of agents made the page slow when every one was built at once. The filter box
    /// still searches all of them.
    /// </summary>
    private void ShowAdminAgentPage()
    {
        Replace(_adminAgents, _adminAgentMatches.Take(_adminAgentsShowing));
        var more = AdminFlow.MoreAgentsLabel(_adminAgents.Count, _adminAgentMatches.Count);
        AdminAgentsMore.Content = more;
        AdminAgentsMore.Visibility = VisibleWhen(more is not null);
    }

    private static void Replace(ObservableCollection<AdminRow> target, IEnumerable<AdminRow> rows)
    {
        target.Clear();
        foreach (var row in rows) target.Add(row);
    }

    /// <summary>On an older bus the Agents tab mirrors the live roster, so it follows roster refreshes.</summary>
    private void RefreshLegacyAdminAgents()
    {
        if (!_adminLegacy) return;
        var now = DateTimeOffset.Now;
        _adminAgentRows = _agentModels.Select(agent => AdminLogic.LegacyAgentRow(agent, now)).ToList();
        ApplyAdminAgentFilter();
    }

    internal async void AdminRowAction_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not AdminRowAction action) return;
        // Device revocation and, on an older bus, blocking go through the server-confirmed flow.
        if (AdminFlow.ConfirmedAction(action.Row) is { } confirmed) await AuthorizeAndAct(confirmed, action.Row.Id, sender);
        else await RunBusy(() => ControlRowAsync(action), sender);
    }

    /// <summary>
    /// Acts on an agent or service principal with an action the bus listed for it: the audit reason
    /// and operator grant first, then the review dialog, then Windows Hello, and only then the request.
    /// </summary>
    private async Task ControlRowAsync(AdminRowAction action)
    {
        var reason = AdminFlow.RequireControl(ActionReason.Text, _api.HasOperatorGrant());
        if (!_platform.Confirm(this, AdminFlow.ControlReview(action), "Review operator action")) return;
        await RequireHelloAsync(AdminFlow.ControlHelloPrompt(action));

        var result = await SendControlAsync(action, reason);
        ShowAdminResult(AdminFlow.ControlResultText(result));
        if (result.Secret is not null)
            ShowOneTimeSecret($"New credential for {result.TargetLabel}", "Shown once and not saved on this PC. The previous secret no longer works.", result.Secret);
        await LoadAdminListsAsync();
        await RefreshAsync();
    }

    private async Task RequireHelloAsync(string prompt)
    {
        if (!await _platform.VerifyHelloAsync(prompt)) throw new InvalidOperationException(AdminFlow.HelloNotCompleted);
    }

    private async Task<ControlResult> SendControlAsync(AdminRowAction action, string reason)
    {
        var row = action.Row;
        try
        {
            return row.Kind == AdminRowKind.Agent
                ? await _api.ControlAgentAsync(row.Id, row.Name, row.Version, action.Action, reason, CancellationToken.None)
                : await _api.ControlServicePrincipalAsync(row.Id, row.Name, row.Version, action.Action, reason, CancellationToken.None);
        }
        catch (BusApiException error) when (error.StatusCode == 409)
        {
            // Someone else changed it first. Show the current state before the operator tries again.
            await LoadAdminListsAsync();
            throw new InvalidOperationException(AdminFlow.ControlConflict(row));
        }
    }

    private void UpdateGrantStatus()
    {
        GrantStatusText.Text = _api.HasOperatorGrant()
            ? "Operator access is saved on this PC, protected for your Windows account. Saving again replaces it."
            : "Not set up yet. The operator password is exchanged once for a revocable grant kept on this PC. The password itself is not stored.";
    }

    internal async void Grant_Click(object sender, RoutedEventArgs e) => await RunBusy(SaveGrantAsync, sender);

    private async Task SaveGrantAsync()
    {
        if (string.IsNullOrWhiteSpace(OperatorPassword.Password) || string.IsNullOrWhiteSpace(GrantReason.Text))
            throw new InvalidOperationException("Enter the operator password and an audit reason.");
        await _api.EstablishGrantAsync(OperatorPassword.Password, GrantReason.Text.Trim(), CancellationToken.None);
        OperatorPassword.Clear();
        ShowAdminResult("Operator access saved for your Windows account on this PC.");
        UpdateGrantStatus();
        UpdateHumansSummary();
    }

    internal async void Freeze_Click(object sender, RoutedEventArgs e) => await AuthorizeAndAct(OperatorAction.ActivateFreeze, "global", sender);
    internal async void ClearFreeze_Click(object sender, RoutedEventArgs e) => await AuthorizeAndAct(OperatorAction.ClearFreeze, "global", sender);

    private Task AuthorizeAndAct(OperatorAction action, string target, object? source) =>
        RunBusy(() => ContainAsync(action, target), source);

    /// <summary>
    /// A containment action the bus confirms first: the audit reason, then the bus's description of
    /// the target and effect for review, then Windows Hello, and only then the action itself.
    /// </summary>
    private async Task ContainAsync(OperatorAction action, string target)
    {
        AdminFlow.RequireReason(ActionReason.Text);
        var confirmation = await _api.RequestConfirmationAsync(action, target, CancellationToken.None);
        if (!_platform.Confirm(this, AdminFlow.ContainmentReview(confirmation), "Review containment action")) return;
        await RequireHelloAsync($"Authorize: {confirmation.Effect}");

        var result = await _api.PerformActionAsync(confirmation, ActionReason.Text.Trim(), CancellationToken.None);
        ShowAdminResult(AdminFlow.ActionResultText(result));
        if (AdminFlow.RevokedThisPc(action, result, target, _api.Session))
        {
            ForgetAndShowEnrollment();
            return;
        }
        await LoadAdminListsAsync();
        await RefreshAsync();
    }

    // ---- Enrollment ---------------------------------------------------------------------------

    private EnrollmentKind SelectedEnrollmentKind =>
        AdminFlow.KindOf(EnrollKindSpn.IsChecked == true, EnrollKindDevice.IsChecked == true);

    private void EnrollKind_Checked(object sender, RoutedEventArgs e)
    {
        if (_ready) UpdateEnrollmentForm();
    }

    private void UpdateEnrollmentForm()
    {
        var form = AdminFlow.Form(SelectedEnrollmentKind);
        EnrollNameLabel.Text = form.NameLabel;
        EnrollSecondPanel.Visibility = VisibleWhen(form.ShowSecond);
        EnrollSecondLabel.Text = form.SecondLabel;
        EnrollSecond.FontFamily = form.MonoSecond ? (System.Windows.Media.FontFamily)FindResource("Mono") : FontFamily;
        EnrollHint.Text = form.Hint;
        EnrollCreateButton.Content = form.CreateLabel;
        UpdateEnrollmentFeedback();
    }

    private void EnrollNaming_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_ready) UpdateEnrollmentFeedback();
    }

    private void UpdateEnrollmentFeedback()
    {
        var kind = SelectedEnrollmentKind;
        ShowNameFeedback(EnrollNameFeedback, AdminFlow.NameFeedback(kind, EnrollName.Text));
        ShowNameFeedback(EnrollSecondFeedback, AdminFlow.SecondFeedback(kind, EnrollSecond.Text));
    }

    private void ShowNameFeedback(TextBlock block, NameFeedback feedback)
    {
        block.Text = feedback.Text;
        block.Visibility = VisibleWhen(feedback.Text.Length > 0);
        block.SetResourceReference(TextBlock.ForegroundProperty, feedback.IsProblem ? "Bad" : "Muted");
    }

    private async void EnrollCreate_Click(object sender, RoutedEventArgs e) => await RunBusy(CreateEnrollmentAsync, sender);

    private async Task CreateEnrollmentAsync()
    {
        var kind = SelectedEnrollmentKind;
        var name = EnrollName.Text.Trim();
        var second = EnrollSecond.Text.Trim();
        var reason = EnrollReason.Text.Trim();
        AdminFlow.RequireEnrollment(kind, name, second, reason, _api.HasOperatorGrant());
        name = AdminFlow.EnrollmentName(kind, name);
        second = AdminFlow.EnrollmentSecond(kind, second);
        await RequireHelloAsync(AdminFlow.EnrollmentHelloPrompt(kind, name));

        var result = await RequestEnrollmentAsync(kind, name, second, reason);
        ShowOneTimeSecret(result.Title, result.Detail, result.Secret);
        EnrollName.Clear();
        EnrollSecond.Clear();
    }

    private Task<EnrollmentResult> RequestEnrollmentAsync(EnrollmentKind kind, string name, string second, string reason) => kind switch
    {
        EnrollmentKind.ServicePrincipal => _api.CreateServicePrincipalAsync(name, second, reason, CancellationToken.None),
        EnrollmentKind.Device => _api.CreateDeviceEnrollmentAsync(name, reason, CancellationToken.None),
        _ => _api.CreateAgentEnrollmentAsync(name, second, reason, CancellationToken.None)
    };

    internal void EnrollCopy_Click(object sender, RoutedEventArgs e)
    {
        if (EnrollResultSecret.Text.Length > 0) CopyToClipboard(EnrollResultSecret.Text);
    }

    /// <summary>The package or secret exists only in this box; clearing it is the only copy leaving the app.</summary>
    internal void EnrollClear_Click(object sender, RoutedEventArgs e) => ClearEnrollmentResult();

    /// <summary>Shows a package or secret the bus returns once. It lives only in this box.</summary>
    private void ShowOneTimeSecret(string title, string detail, string? secret)
    {
        EnrollResultTitle.Text = title;
        EnrollResultDetail.Text = detail;
        EnrollResultSecret.Text = secret ?? string.Empty;
        EnrollResultSecret.Visibility = VisibleWhen(secret is not null);
        EnrollCopyButton.Visibility = EnrollResultSecret.Visibility;
        EnrollResultPanel.Visibility = Visibility.Visible;
        AdminPage.ScrollToTop();
    }

    private void ClearEnrollmentResult()
    {
        EnrollResultSecret.Clear();
        EnrollResultPanel.Visibility = Visibility.Collapsed;
    }

    private void ShowAdminResult(string message)
    {
        AdminResult.Text = message;
        AdminResultPanel.Visibility = Visibility.Visible;
    }

    // ---- Export ------------------------------------------------------------------------------

    internal void ExportLastDay_Click(object sender, RoutedEventArgs e) =>
        SetExportWindow(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now);

    internal void ClearExportFilter_Click(object sender, RoutedEventArgs e)
    {
        ExportFrom.Clear();
        ExportTo.Clear();
    }

    private void SetExportWindow(DateTimeOffset from, DateTimeOffset to)
    {
        ExportFrom.Text = AdminFlow.ExportBoundary(from);
        ExportTo.Text = AdminFlow.ExportBoundary(to.AddMinutes(1));
    }

    internal async void ExportCsv_Click(object sender, RoutedEventArgs e) => await RunBusy(ExportCsvAsync, sender);

    private async Task ExportCsvAsync()
    {
        var (from, to) = AdminFlow.ExportWindow(ExportFrom.Text, ExportTo.Text);
        var filtered = AdminFlow.SelectExport(await _api.GetExportMessagesAsync(CancellationToken.None), from, to);
        if (_platform.PickExportPath(this, AdminFlow.ExportFileName(DateTime.Now)) is not { } path) return;

        await File.WriteAllTextAsync(path, BuildCsv(filtered), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        ShowAdminResult(AdminFlow.ExportSaved(Path.GetFileName(path), filtered.Count));
    }

    internal static string BuildCsv(IReadOnlyCollection<BusMessage> messages)
    {
        var lines = new List<string>
        {
            "sequence,created_at_utc,created_at_local,channel,agent,kind,body,body_sha256,csv_sanitized"
        };
        foreach (var message in messages.OrderBy(message => message.Seq))
        {
            var bodyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(message.Body))).ToLowerInvariant();
            var values = new[]
            {
                message.Seq.ToString(CultureInfo.InvariantCulture),
                message.CreatedAt.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
                message.CreatedAt.ToLocalTime().ToString("O", CultureInfo.InvariantCulture),
                message.Channel,
                message.AgentName,
                message.Kind,
                message.Body,
                bodyHash
            };
            var sanitized = values.Any(RequiresSpreadsheetSanitization);
            lines.Add(string.Join(",", values.Select(value => EscapeCsv(SanitizeSpreadsheetCell(value))).Append(sanitized ? "true" : "false")));
        }

        return string.Join(Environment.NewLine, lines) + Environment.NewLine;
    }

    /// <summary>The characters a spreadsheet takes as the start of a formula.</summary>
    private const string FormulaLeads = "=+-@\t\r";

    private static bool RequiresSpreadsheetSanitization(string value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        var firstSignificant = value.AsSpan().TrimStart();
        return !firstSignificant.IsEmpty && FormulaLeads.Contains(firstSignificant[0]);
    }

    private static string SanitizeSpreadsheetCell(string value) =>
        RequiresSpreadsheetSanitization(value) ? "'" + value : value;

    private static string EscapeCsv(string value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var escaped = value.Replace("\"", "\"\"");
        return value.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? $"\"{escaped}\"" : escaped;
    }
}
