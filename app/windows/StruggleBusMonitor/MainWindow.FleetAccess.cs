using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows;

namespace StruggleBusMonitor;

/// <summary>
/// Admin, Worker hosts: who may task the hosts. The operator picks an agent from the bus's own
/// list and says where it may work; the app composes the fleet change, asks the hardware key to
/// sign it and publishes it. Removing a coordinator or a host goes the same way.
/// </summary>
public partial class MainWindow
{
    private readonly ObservableCollection<FleetEntryRow> _fleetEntries = [];
    private readonly ObservableCollection<AgentChoice> _accessChoices = [];

    /// <summary>Every agent that could be authorised. Only those matching the search box are put on screen.</summary>
    private IReadOnlyList<AgentChoice> _accessAllChoices = [];
    private AgentChoice? _accessAgent;

    private void InitializeFleetAccess()
    {
        FleetEntriesList.ItemsSource = _fleetEntries;
        AccessAgentsList.ItemsSource = _accessChoices;
    }

    internal async void FleetAccessReload_Click(object sender, RoutedEventArgs e) => await RunBusy(LoadFleetAccessAsync, sender);

    /// <summary>
    /// Shows what the fleet on the bus lists and which agents could be authorised. Nothing is
    /// trusted from this reading: every change reads the fleet again and verifies its signature.
    /// </summary>
    private async Task LoadFleetAccessAsync()
    {
        if (_api.Session is null) return;
        var fleet = await ListedFleetAsync();
        var agents = await ManagedAgentsOrNoneAsync();
        Replace(_fleetEntries, FleetAccessLogic.Rows(fleet));
        _accessAllChoices = FleetAccessLogic.Choices(agents, fleet, DateTimeOffset.Now);
        ShowAccessMatches();
        ChooseAccessAgent(_accessAllChoices.FirstOrDefault(choice => choice.Id == _accessAgent?.Id));
        FleetAccessSummary.Text = fleet.Count == 0
            ? "The bus holds no fleet yet, or one this app cannot read. Publish today's signed fleet first, below."
            : $"The fleet on the bus lists {_fleetEntries.Count(row => row.Kind == "coordinator")} agent(s) that may task the hosts and {_fleetEntries.Count(row => row.Kind == "host")} worker host(s).";
    }

    private static void Replace<T>(ObservableCollection<T> list, IEnumerable<T> items)
    {
        list.Clear();
        foreach (var item in items) list.Add(item);
    }

    /// <summary>What the bus's fleet lists, for display. An older bus, no fleet, or one outside the strict reading shows as empty.</summary>
    private async Task<IReadOnlyList<FleetAgent>> ListedFleetAsync()
    {
        try
        {
            var stored = await _api.GetSiteDocumentAsync(FleetPublishLogic.DocumentName, CancellationToken.None);
            return stored is null ? [] : FleetCompose.Agents(Encoding.UTF8.GetString(stored.Body));
        }
        catch (Exception error) when (error is FleetRefusedException || (error is BusApiException bus && AdminFlow.IsLegacyBus(bus)))
        {
            return [];
        }
    }

    private async Task<List<ManagedAgent>> ManagedAgentsOrNoneAsync()
    {
        try
        {
            return await _api.GetManagedAgentsAsync(includeRetired: false, CancellationToken.None);
        }
        catch (BusApiException error) when (AdminFlow.IsLegacyBus(error))
        {
            return [];
        }
    }

    internal void AccessAgent_Click(object sender, RoutedEventArgs e) => ChooseAccessAgent(TagOf<AgentChoice>(sender));

    internal void AccessAgentSearch_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) => ShowAccessMatches();

    /// <summary>Puts the few agents that match the search on screen, and says how many more there are.</summary>
    private void ShowAccessMatches()
    {
        Replace(_accessChoices, FleetAccessLogic.Matching(_accessAllChoices, AccessAgentSearch.Text));
        AccessAgentSearchText.Text = FleetAccessLogic.SearchText(_accessAllChoices, AccessAgentSearch.Text);
    }

    /// <summary>
    /// Keeps the site's repository locations as soon as the operator leaves the box, so they are
    /// there after a restart without a host having to be created first.
    /// </summary>
    internal void HostRemotes_LostFocus(object sender, RoutedEventArgs e) => KeepRemotes();

    private void KeepRemotes()
    {
        if (_settings.HostRemotes == HostRemotes.Text) return;
        _settings.HostRemotes = HostRemotes.Text;
        _settings.Save();
    }

    private void ChooseAccessAgent(AgentChoice? agent)
    {
        _accessAgent = agent;
        AccessAgentText.Text = agent is null ? "No agent chosen yet." : "Chosen:  " + agent.Identity;
    }

    private AccessForm ReadAccessForm() => new(
        _accessAgent, AccessProject.Text, AccessNotesRepo.Text, AccessNotesChannel.Text, AccessRepos.Text);

    internal async void AccessAuthorise_Click(object sender, RoutedEventArgs e) => await RunBusy(AuthoriseAgentAsync, sender);

    /// <summary>
    /// Every check on the values comes first, then the fleet on the bus is read and verified, then
    /// the operator is told in full what the agent will be able to do, and only then is anything
    /// signed.
    /// </summary>
    private async Task AuthoriseAgentAsync()
    {
        if (!_api.HasOperatorGrant()) throw new InvalidOperationException(AdminFlow.GrantNeeded);
        var remotes = AddHostLogic.Lines(HostRemotes.Text);
        if (remotes.Count == 0) throw new InvalidOperationException(FleetAccessLogic.NoRemotes);
        KeepRemotes();
        var entry = FleetAccessLogic.Entry(ReadAccessForm());
        var agent = _accessAgent!;

        var change = await ComposeChangeAsync(current =>
        {
            var (next, broad) = FleetAllowList.Add(current.Text, entry, current.BusSerial, ReportedFleetSerials(), remotes);
            var hosts = FleetCompose.Agents(current.Text).Count(listed => listed.Kind == "host");
            return (next, FleetAccessLogic.AuthoriseText(entry, agent, hosts, broad));
        });
        if (!_platform.Confirm(this, change.Question, FleetAccessLogic.AuthoriseCaption)) return;
        await FinishChangeAsync(change, FleetAccessLogic.Authorises(entry.AgentName));
    }

    internal async void FleetEntryRemove_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<FleetEntryRow>(sender) is { } row) await RunBusy(() => RemoveFleetEntryAsync(row), sender);
    }

    private async Task RemoveFleetEntryAsync(FleetEntryRow row)
    {
        if (!_api.HasOperatorGrant()) throw new InvalidOperationException(AdminFlow.GrantNeeded);
        var change = await ComposeChangeAsync(current =>
            (FleetAllowList.Remove(current.Text, row.Kind, row.Name, current.BusSerial, ReportedFleetSerials()), FleetAccessLogic.RemoveText(row)));
        if (!_platform.Confirm(this, change.Question, FleetAccessLogic.RemoveCaption)) return;
        await FinishChangeAsync(change, FleetAccessLogic.Removes(row));
    }

    /// <summary>Reads and verifies the fleet on the bus, then composes the next one. A refusal comes back in words with a way forward.</summary>
    private async Task<(byte[] Next, long Serial, string Question)> ComposeChangeAsync(Func<(string Text, long BusSerial), (string Next, string Question)> compose)
    {
        var current = await ReadCurrentFleetAsync();
        try
        {
            var (next, question) = compose((Encoding.UTF8.GetString(current.Fleet.Body), current.BusSerial));
            return (new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(next), current.BusSerial + 1, question);
        }
        catch (FleetRefusedException refusal)
        {
            throw new InvalidOperationException(FleetAccessLogic.RefusalText(refusal));
        }
    }

    /// <summary>Signs and publishes when a hardware key can be asked on this PC; otherwise saves the document for signing elsewhere.</summary>
    private async Task FinishChangeAsync((byte[] Next, long Serial, string Question) change, string words)
    {
        var result = SigningKeyHere() is { } key
            ? await SignAndPublishAsync(change.Next, words, key)
            : await HandOverForSigningAsync(change.Next, change.Serial, words);
        ShowFleetResult(result ?? FleetJoinLogic.NothingChanged);
        await LoadFleetAccessAsync();
    }

    private async Task<string?> HandOverForSigningAsync(byte[] next, long serial, string words)
    {
        if (_platform.PickFleetSavePath(this) is not { } path) return null;
        await File.WriteAllBytesAsync(path, next);
        await File.WriteAllTextAsync(FleetJoinLogic.SignersPath(path), FleetJoinLogic.SignersFile(FleetPublishLogic.Signers(HostSigners.Text)));
        _composedFleet = next;
        _composedFor = words;
        return FleetAccessLogic.SavedText(path, serial, words);
    }
}
