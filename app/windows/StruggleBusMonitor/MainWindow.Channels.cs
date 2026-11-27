using System.Collections.ObjectModel;
using System.Windows;

namespace StruggleBusMonitor;

/// <summary>The Channels page: what each channel is for, how busy it is and who is listening.</summary>
public partial class MainWindow
{
    private readonly ObservableCollection<ChannelCard> _channelCards = [];

    /// <summary>When the page was last filled from the bus. Null until it has been, and after a new enrollment.</summary>
    private DateTimeOffset? _channelsLoadedAt;

    private void InitializeChannels() => ChannelsList.ItemsSource = _channelCards;

    private void OnChannelsPageShown()
    {
        if (ChannelsPageLogic.IsStale(_channelsLoadedAt, DateTimeOffset.Now)) _ = RunBusy(LoadChannelsPageAsync);
    }

    internal async void ChannelsReload_Click(object sender, RoutedEventArgs e) => await RunBusy(LoadChannelsPageAsync, sender);

    private async Task LoadChannelsPageAsync()
    {
        if (_api.Session is null) return;
        var (channels, withFigures) = await ReadChannelsAsync();
        var now = DateTimeOffset.Now;
        var cards = channels.Select(channel => ChannelsPageLogic.Card(channel, now)).ToList();
        _channelCards.Clear();
        foreach (var card in cards) _channelCards.Add(card);
        ChannelsSummary.Text = ChannelsPageLogic.Summary(cards, withFigures);
        _channelsLoadedAt = now;
    }

    /// <summary>Every channel with its figures; from a bus too old to count, the names and purposes alone.</summary>
    private async Task<(IReadOnlyList<ChannelActivity> Channels, bool WithFigures)> ReadChannelsAsync()
    {
        try
        {
            return (await _api.GetChannelActivityAsync(CancellationToken.None), true);
        }
        catch (BusApiException error) when (AdminFlow.IsLegacyBus(error))
        {
            return (ChannelsPageLogic.WithoutFigures(await _api.GetChannelsAsync(CancellationToken.None)), false);
        }
    }

    /// <summary>Opens Monitor showing only that channel's messages.</summary>
    internal void ChannelShow_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<ChannelCard>(sender) is not { } card) return;
        MonitorNav.IsChecked = true;
        MessageFilterBox.Clear();
        SelectAgent(null);
        SelectChannel(card.Name);
    }
}
