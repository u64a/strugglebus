using System.Collections.ObjectModel;
using System.Windows;

namespace StruggleBusMonitor;

/// <summary>The Hosts page: what each worker host last reported to the bus, and its last twelve hours.</summary>
public partial class MainWindow
{
    private readonly ObservableCollection<HostCard> _hostCards = [];

    /// <summary>When the page was last filled from the bus. Null until it has been, and after a new enrollment.</summary>
    private DateTimeOffset? _hostsLoadedAt;
    private bool _hostsRefreshing;

    private void InitializeHosts() => HostsList.ItemsSource = _hostCards;

    private void OnHostsPageShown()
    {
        if (HostsPageLogic.IsStale(_hostsLoadedAt, DateTimeOffset.Now)) _ = RunBusy(LoadHostsPageAsync);
        _ = KeepHostsFreshAsync();
    }

    internal async void HostsReload_Click(object sender, RoutedEventArgs e) => await RunBusy(LoadHostsPageAsync, sender);

    private bool HostsPageShowing => !_shutdownStarted && HostsPage.Visibility == Visibility.Visible && WorkspacePanel.Visibility == Visibility.Visible;

    /// <summary>
    /// Reloads the page every half minute for as long as it is the page showing. It stops by itself
    /// when another page is opened, and starts again the next time this one is.
    /// </summary>
    private async Task KeepHostsFreshAsync()
    {
        if (_hostsRefreshing) return;
        _hostsRefreshing = true;
        await WindowLogic.RepeatAsync(
            _platform.Delay, HostsPageLogic.RefreshEvery, HostsPageLogic.RefreshEvery, () => !HostsPageShowing, RefreshHostsQuietlyAsync);
        _hostsRefreshing = false;
    }

    /// <summary>A refresh nobody asked for must not raise a notice: what went wrong is said on the page itself.</summary>
    private async Task RefreshHostsQuietlyAsync()
    {
        try { await LoadHostsPageAsync(); }
        catch (Exception error) { HostsSummary.Text = $"Could not refresh the hosts: {error.Message}"; }
    }

    /// <summary>
    /// Every marked host with its last report and history. With operator access saved the bus sends
    /// each report whole; without it the account, warnings and channel are left out.
    /// </summary>
    private async Task LoadHostsPageAsync()
    {
        if (_api.Session is null) return;
        var whole = _api.HasOperatorGrant();
        HostsStatus status;
        try
        {
            status = await _api.GetHostsStatusAsync(whole, CancellationToken.None);
        }
        catch (BusApiException error) when (AdminFlow.IsLegacyBus(error))
        {
            ShowHosts([], HostsPageLogic.Unsupported);
            return;
        }
        var cards = status.Hosts.Select(host => HostsPageLogic.Card(host, status.Now)).ToList();
        foreach (var card in cards)
            HostsPageLogic.Draw(card, await _api.GetHostHistoryAsync(card.AgentId, CancellationToken.None), status.Now);
        ShowHosts(cards, HostsPageLogic.Summary(cards, whole));
        _hostsLoadedAt = DateTimeOffset.Now;
    }

    private void ShowHosts(IReadOnlyList<HostCard> cards, string summary)
    {
        _hostCards.Clear();
        foreach (var card in cards) _hostCards.Add(card);
        HostsSummary.Text = summary;
    }
}
