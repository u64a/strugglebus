using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;

namespace StruggleBusMonitor;

/// <summary>
/// Monitor page: live feed, agent list, filters and the background refresh loops. The rules are in
/// <see cref="MonitorFeedLogic"/>, <see cref="MonitorStreamTracker"/> and <see cref="MonitorLogic"/>.
/// </summary>
public partial class MainWindow
{
    private const int HistoryPageSize = 200;

    /// <summary>How the background loops wait. Tests replace it so no test has to wait for real.</summary>
    internal Func<TimeSpan, CancellationToken, Task> Pause { get; set; } = Task.Delay;

    /// <summary>Where the Copy buttons on message rows put their text. Tests replace it so they leave the real clipboard alone.</summary>
    internal Action<string> CopyText { get; set; } = _ => { };

    private bool _historySupported;
    private readonly ObservableCollection<ActivityEntry> _activity = [];
    private readonly HashSet<long> _knownActivitySequences = [];
    private readonly List<BusMessage> _pendingActivity = [];
    private readonly ObservableCollection<AgentEntry> _agents = [];
    private List<BusAgent> _agentModels = [];
    private ICollectionView _activityView = null!;
    private ICollectionView _agentView = null!;
    private ScrollViewer? _activityScroll;
    private string? _selectedChannel;
    private string? _selectedAgent;
    private string _messageFilter = string.Empty;
    private bool _updatingChannelFilter;
    private bool _updatingAgentSelection;

    private void InitializeMonitor()
    {
        CopyText = CopyToClipboard;
        _activityView = CollectionViewSource.GetDefaultView(_activity);
        _activityView.Filter = item => item is ActivityEntry entry && FeedLogic.Matches(entry.Message, CurrentFeedQuery());
        ActivityList.ItemsSource = _activityView;

        _agentView = CollectionViewSource.GetDefaultView(_agents);
        _agentView.Filter = item => item is AgentEntry entry && FeedLogic.MatchesAgent(entry.Agent, AgentFilterBox.Text);
        AgentList.ItemsSource = _agentView;
    }

    private FeedQuery CurrentFeedQuery() => new(_messageFilter, _selectedAgent, _selectedChannel);

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RunBusy(RefreshAsync, sender);

    private async Task RefreshAsync()
    {
        var snapshotTask = _api.GetSnapshotAsync(CancellationToken.None);
        var channelsTask = _api.GetChannelsAsync(CancellationToken.None);
        await Task.WhenAll(snapshotTask, channelsTask);
        var snapshot = await snapshotTask;
        var channels = await channelsTask;
        ShowSnapshot(snapshot);

        // A busy board pushes #humans out of the global snapshot, so load its own history first.
        _historySupported = await _api.ProbeHistoryAsync(CancellationToken.None);
        await LoadHumansHistoryAsync();
        RecordHumansMessages(snapshot.Messages);
        UpdateChannelFilter(channels);
        SyncAgents(snapshot.Agents);
        UpdateActivitySummary();
        if (_selectedAgent is { } agent) _ = LoadAgentHistoryAsync(agent);
        await RestartMonitorAsync();
    }

    private void ShowStatus(StatusDisplay status) => SetConnectionState(status.State, status.Detail, status.Tone);

    /// <summary>Replaces the feed with the snapshot's messages and shows the bus as live or frozen.</summary>
    private void ShowSnapshot(Snapshot snapshot)
    {
        _isFrozen = MonitorFeedLogic.IsFrozenState(snapshot.State);
        ShowStatus(MonitorFeedLogic.LiveStatus(_isFrozen, MonitorFeedLogic.SequenceDetail(snapshot.LatestSeq)));

        var now = DateTimeOffset.Now;
        NoteConnected();
        NoteConnection(_tracker.ReportFrozen(now, _isFrozen));
        foreach (var item in snapshot.Messages) NoteMaintenance(item);
        _pendingActivity.Clear();
        _knownActivitySequences.Clear();
        _activity.Clear();
        foreach (var item in snapshot.Messages.OrderByDescending(message => message.Seq))
        {
            _activity.Add(new ActivityEntry(item, now) { Highlight = _messageFilter });
            _knownActivitySequences.Add(item.Seq);
        }
        UpdateHoldBar();
    }

    private async Task LoadHumansHistoryAsync()
    {
        if (!_historySupported) return;
        try
        {
            RecordHumansMessages(await _api.GetHistoryAsync(HumansLogic.Channel, null, null, HistoryPageSize, CancellationToken.None));
        }
        catch (BusApiException)
        {
            // No #humans channel yet; the global snapshot still applies.
        }
    }

    /// <summary>Adds one agent's older messages to the feed so its filter shows more than the live window.</summary>
    private async Task LoadAgentHistoryAsync(string agentName)
    {
        if (!_historySupported) return;
        try
        {
            var history = await _api.GetHistoryAsync(null, agentName, null, HistoryPageSize, CancellationToken.None);
            if (_selectedAgent != agentName) return;
            foreach (var message in history)
                if (_knownActivitySequences.Add(message.Seq)) InsertActivity(message, pinned: true);
            UpdateActivitySummary();
        }
        catch (Exception error)
        {
            ShowNotice($"Could not load {agentName}'s older messages: {error.Message}");
        }
    }

    private void DropPinnedActivity()
    {
        foreach (var sequence in MonitorFeedLogic.RemovePinned(_activity)) _knownActivitySequences.Remove(sequence);
    }

    // ---- Background loops --------------------------------------------------------------------

    private Task RestartMonitorAsync()
    {
        if (_shutdownStarted) return Task.CompletedTask;
        return _monitorLifecycle.RestartAsync(cancellation => _shutdownStarted
            ? []
            :
            [
                MaintainStreamAsync(cancellation),
                MaintainFeedReconciliationAsync(cancellation.Token),
                MaintainDirectoryRefreshAsync(cancellation.Token)
            ]);
    }

    private Task StopMonitorAsync() => _monitorLifecycle.StopAsync();

    private async Task MaintainFeedReconciliationAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Pause(TimeSpan.FromSeconds(10), cancellationToken);
                var messages = await _api.GetRecentMessagesAsync(cancellationToken);
                await Dispatcher.InvokeAsync(() => ReconcileFeed(messages));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                await ShowDegradedStateAsync($"Snapshot check failed: {error.Message}");
                try { await Pause(TimeSpan.FromSeconds(5), cancellationToken); }
                catch (OperationCanceledException) { return; }
            }
        }
    }

    private void ReconcileFeed(IEnumerable<BusMessage> messages)
    {
        foreach (var message in messages) AddActivityMessage(message);
        // The bus answers again, so do not leave the stream sitting out its retry wait.
        if (_tracker.IsDown) KickStream();
    }

    /// <summary>Keeps the channel list and the agent list (and so presence) current.</summary>
    private async Task MaintainDirectoryRefreshAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Pause(TimeSpan.FromSeconds(15), cancellationToken);
                var channels = await _api.GetChannelsAsync(cancellationToken);
                var agents = await _api.GetAgentsAsync(cancellationToken);
                await Dispatcher.InvokeAsync(() => ShowDirectory(channels, agents));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                await ShowDegradedStateAsync($"Agent and channel refresh failed: {error.Message}");
            }
        }
    }

    private void ShowDirectory(IReadOnlyCollection<BusChannel> channels, IReadOnlyCollection<BusAgent> agents)
    {
        UpdateChannelFilter(channels);
        SyncAgents(agents);
    }

    /// <summary>The bus no longer accepts this PC's credential, at startup or mid-stream: say so and offer to enroll again.</summary>
    private void ShowRevoked(string detail)
    {
        SetConnectionState("REVOKED", string.Empty, "Bad");
        NoteConnection(new ConnectionEvent(DateTimeOffset.Now, "Bad", "This PC's access was revoked on the bus. It must be enrolled again."));
        ShowNotice(detail + " Enroll this PC again to continue.", "Enroll again", ForgetAndShowEnrollment);
    }

    private CancellationTokenSource _streamKick = new();

    /// <summary>Makes the stream loop reconnect now instead of finishing a retry wait or a read that has gone quiet.</summary>
    private void KickStream() => Interlocked.Exchange(ref _streamKick, new CancellationTokenSource()).Cancel();

    private void ShowStreamLive()
    {
        if (!_tracker.IsDown) return;
        ShowStatus(MonitorFeedLogic.LiveStatus(_isFrozen, string.Empty));
        NoteConnected();
    }

    /// <summary>
    /// A bus that is shutting down can still accept a stream and end it at once, so after an outage
    /// the stream only counts as back when it has stayed open for a moment or delivered a message.
    /// </summary>
    private async Task ConfirmStreamOpenAsync(CancellationToken attempt)
    {
        try
        {
            await Pause(TimeSpan.FromSeconds(2), attempt);
            await Dispatcher.InvokeAsync(ShowStreamLive);
        }
        catch (OperationCanceledException)
        {
            // The stream ended first; the loop reports why.
        }
    }

    private async Task MaintainStreamAsync(CancellationTokenSource cancellation)
    {
        var tracker = new MonitorStreamTracker();
        while (!cancellation.IsCancellationRequested)
        {
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token, _streamKick.Token);
            if (!await RunStreamAttemptAsync(tracker, cancellation, attempt)) return;
        }
    }

    /// <summary>One connection to the stream and the wait that follows it. False ends the loop.</summary>
    private async Task<bool> RunStreamAttemptAsync(MonitorStreamTracker tracker, CancellationTokenSource cancellation, CancellationTokenSource attempt)
    {
        try
        {
            var end = await ReadStreamAsync(attempt.Token);
            if (cancellation.IsCancellationRequested) return false;

            var step = tracker.OnEnd(end);
            await Dispatcher.InvokeAsync(() => ShowStreamEnd(step, end.Detail));
            if (step.Stops)
            {
                cancellation.Cancel();
                return false;
            }
            await Pause(step.Delay, attempt.Token);
            return true;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            return false;
        }
        catch (OperationCanceledException) when (attempt.IsCancellationRequested)
        {
            // Kicked: go round and connect straight away.
            return true;
        }
        catch (Exception error)
        {
            return await WaitAfterStreamErrorAsync(tracker.OnError(), error, cancellation, attempt.Token);
        }
    }

    /// <summary>
    /// Always the global stream: filters are applied locally so #humans, unread counts and search
    /// keep receiving every channel whatever the feed is narrowed to.
    /// </summary>
    private async Task<StreamEnd> ReadStreamAsync(CancellationToken attempt)
    {
        using var open = CancellationTokenSource.CreateLinkedTokenSource(attempt);
        try
        {
            return await _api.StreamAsync(
                null,
                () =>
                {
                    _ = ConfirmStreamOpenAsync(open.Token);
                    return Task.CompletedTask;
                },
                message => Dispatcher.InvokeAsync(() => ShowStreamMessage(message)).Task,
                attempt);
        }
        finally
        {
            open.Cancel();
        }
    }

    private void ShowStreamMessage(BusMessage message)
    {
        ShowStreamLive();
        AddActivityMessage(message);
    }

    private void ShowStreamEnd(StreamStep step, string detail)
    {
        if (step.Stops)
        {
            ShowRevoked(detail);
            return;
        }
        if (step.Disposition == StreamDisposition.RetryFrozen) _isFrozen = true;
        NoteConnection(MonitorStreamTracker.Report(_tracker, step.Disposition, detail, DateTimeOffset.Now));
        if (step.Status is { } status) ShowStatus(status);
        if (step.Notice is { } notice) ShowNotice(notice);
    }

    /// <summary>Waits out a failed connection. A kick ends the wait early; false means the loops are stopping.</summary>
    private async Task<bool> WaitAfterStreamErrorAsync(TimeSpan delay, Exception error, CancellationTokenSource cancellation, CancellationToken attempt)
    {
        await ShowDegradedStateAsync($"Reconnecting: {error.Message}");
        try { await Pause(delay, attempt); }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested) { }
        catch (OperationCanceledException) { return false; }
        return true;
    }

    // ---- Feed --------------------------------------------------------------------------------

    private bool IsReadingBack => (_activityScroll ??= FindScrollViewer(ActivityList)) is { VerticalOffset: > 1 };

    private void AddActivityMessage(BusMessage message)
    {
        RecordHumansMessages([message]);
        if (!_knownActivitySequences.Add(message.Seq)) return;
        NoteMaintenance(message);

        if (!_isFrozen) ShowStatus(MonitorFeedLogic.LiveStatus(false, MonitorFeedLogic.SequenceDetail(message.Seq)));

        // Inserting above someone who has scrolled down would push what they are reading off screen,
        // so new messages wait until they return to the top or ask for them.
        if (IsReadingBack)
        {
            _pendingActivity.Add(message);
            UpdateHoldBar();
            return;
        }
        InsertActivity(message);
        UpdateActivitySummary();
    }

    private void InsertActivity(BusMessage message, bool pinned = false)
    {
        MonitorFeedLogic.InsertBySequence(_activity, new ActivityEntry(message, DateTimeOffset.Now) { Highlight = _messageFilter, Pinned = pinned });
        foreach (var sequence in MonitorFeedLogic.TrimLive(_activity)) _knownActivitySequences.Remove(sequence);
    }

    private void FlushPendingActivity()
    {
        if (_pendingActivity.Count == 0) return;
        foreach (var message in _pendingActivity.OrderBy(message => message.Seq))
            InsertActivity(message);
        _pendingActivity.Clear();
        UpdateHoldBar();
        UpdateActivitySummary();
    }

    private void UpdateHoldBar()
    {
        var count = _pendingActivity.Count;
        ActivityHoldBar.Visibility = VisibleWhen(count > 0);
        ActivityHoldText.Text = MonitorFeedLogic.HoldText(count);
    }

    private void ActivityJump_Click(object sender, RoutedEventArgs e)
    {
        FlushPendingActivity();
        _activityScroll?.ScrollToTop();
    }

    private void ActivityList_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (e.VerticalChange != 0 && e.VerticalOffset <= 1) FlushPendingActivity();
    }

    private void UpdateActivitySummary()
    {
        var shown = _activityView.Cast<object>().Count();
        ActivityCountText.Text = MonitorFeedLogic.ActivityCountText(shown, _activity.Count);
        EmptyActivityText.Visibility = VisibleWhen(shown == 0);
        EmptyActivityText.Text = MonitorFeedLogic.EmptyActivityText(_activity.Count);
        MonitorFeedLogic.ApplyMessageCounts(_agents, _activity);
    }

    private void RefreshFeedFilter()
    {
        _activityView.Refresh();
        UpdateActivitySummary();
    }

    private void MessageFilterBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready) return;
        _messageFilter = MessageFilterBox.Text.Trim();
        foreach (var entry in _activity) entry.Highlight = _messageFilter;
        RefreshFeedFilter();
    }

    private void ActivityList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ActivityList.SelectedItem is ActivityEntry entry) entry.IsExpanded = !entry.IsExpanded;
    }

    private void ExpandMessage_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<ActivityEntry>(sender) is { } entry) entry.IsExpanded = !entry.IsExpanded;
    }

    private void CopyMessage_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<ActivityEntry>(sender) is { } entry) CopyText(entry.Message.Body);
    }

    private void ReplyToMessage_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<ActivityEntry>(sender) is { } entry) HandOffToHumans(entry.Message, quote: false);
    }

    private void QuoteMessage_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<ActivityEntry>(sender) is { } entry) HandOffToHumans(entry.Message, quote: true);
    }

    /// <summary>
    /// Opens Humans with a draft about a message. Monitor stays read-only: this only moves to the
    /// other page and fills in a draft, and nothing is sent until the operator sends it there.
    /// </summary>
    private void HandOffToHumans(BusMessage message, bool quote)
    {
        HumansNav.IsChecked = true;
        // The bus links a reply only to a message in the same channel, and the operator posts in #humans.
        if (!quote && ReplyHandOff.CanLink(message)) StartReply(message);
        HumansComposer.Text = ReplyHandOff.Merge(HumansComposer.Text, quote ? ReplyHandOff.QuoteDraft(message) : ReplyHandOff.ReplyDraft(message));
        HumansComposer.CaretIndex = HumansComposer.Text.Length;
        HumansComposer.Focus();
    }

    /// <summary>Clears the filters, then selects, expands and scrolls to one message.</summary>
    private void JumpToMessage(BusMessage message)
    {
        MonitorNav.IsChecked = true;
        MessageFilterBox.Clear();
        SelectAgent(null);
        SelectChannel(null);
        FlushPendingActivity();
        if (_knownActivitySequences.Add(message.Seq)) InsertActivity(message, pinned: true);
        UpdateActivitySummary();
        if (_activity.FirstOrDefault(entry => entry.Sequence == message.Seq) is not { } target) return;
        target.IsExpanded = true;
        ActivityList.SelectedItem = target;
        ActivityList.ScrollIntoView(target);
    }

    // ---- Channels ----------------------------------------------------------------------------

    private void UpdateChannelFilter(IReadOnlyCollection<BusChannel> channels)
    {
        var normalized = MonitorLogic.NormalizeChannelSelection(_selectedChannel, channels);
        var selectionLost = normalized != _selectedChannel;
        _selectedChannel = normalized;

        var names = channels.Select(channel => channel.Name).ToList();
        if (MonitorFeedLogic.ChannelChipsOutdated(ChannelFilter.Items.Cast<ChannelFilterOption>().ToList(), names))
        {
            _updatingChannelFilter = true;
            ChannelFilter.Items.Clear();
            ChannelFilter.Items.Add(new ChannelFilterOption(null));
            foreach (var name in names) ChannelFilter.Items.Add(new ChannelFilterOption(name));
            _updatingChannelFilter = false;
        }
        SelectChannel(_selectedChannel);
        if (selectionLost) RefreshFeedFilter();
    }

    private void SelectChannel(string? name)
    {
        var changed = _selectedChannel != name;
        _selectedChannel = name;
        _updatingChannelFilter = true;
        ChannelFilter.SelectedItem = ChannelFilter.Items.Cast<ChannelFilterOption>().FirstOrDefault(option => option.Name == name);
        _updatingChannelFilter = false;
        if (changed) RefreshFeedFilter();
    }

    private void ChannelFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_updatingChannelFilter || ChannelFilter.SelectedItem is not ChannelFilterOption option || option.Name == _selectedChannel)
            return;
        _selectedChannel = option.Name;
        RefreshFeedFilter();
    }

    // ---- Agents ------------------------------------------------------------------------------

    /// <summary>Updates the agent rows in place so selection and scroll position survive a refresh.</summary>
    private void SyncAgents(IReadOnlyCollection<BusAgent> agents)
    {
        _agentModels = agents.ToList();
        _updatingAgentSelection = true;
        MonitorFeedLogic.SyncAgentRows(_agents, agents, DateTimeOffset.Now);
        _updatingAgentSelection = false;

        if (MonitorFeedLogic.SelectedAgentGone(_selectedAgent, _agents)) SelectAgent(null);
        UpdateAgentSummary();
        RefreshLegacyAdminAgents();
        RefreshMentionPopup();
    }

    private void UpdateAgentSummary()
    {
        var shown = _agentView.Cast<object>().Count();
        AgentCountText.Text = MonitorFeedLogic.AgentCountText(shown, _agents.Count);
        AgentEmptyText.Visibility = VisibleWhen(shown == 0 && _agents.Count > 0);
    }

    private void AgentFilterBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready) return;
        _updatingAgentSelection = true;
        _agentView.Refresh();
        AgentList.SelectedItem = _agents.FirstOrDefault(agent => agent.Name == _selectedAgent);
        _updatingAgentSelection = false;
        UpdateAgentSummary();
    }

    /// <summary>Clicking the agent that is already selected clears the filter.</summary>
    private void AgentList_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject source &&
            ItemsControl.ContainerFromElement(AgentList, source) is ListBoxItem { IsSelected: true })
        {
            e.Handled = true;
            SelectAgent(null);
        }
    }

    private void AgentList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_updatingAgentSelection) return;
        SelectAgent((AgentList.SelectedItem as AgentEntry)?.Name);
    }

    private void SelectAgent(string? name)
    {
        var changed = _selectedAgent != name;
        _selectedAgent = name;
        _updatingAgentSelection = true;
        AgentList.SelectedItem = _agents.FirstOrDefault(agent => agent.Name == name);
        _updatingAgentSelection = false;
        AgentChip.Visibility = VisibleWhen(name is not null);
        AgentChip.Content = MonitorFeedLogic.AgentChipText(name);
        if (!changed) return;
        DropPinnedActivity();
        RefreshFeedFilter();
        if (name is not null) _ = LoadAgentHistoryAsync(name);
    }

    private void AgentChip_Click(object sender, RoutedEventArgs e) => SelectAgent(null);
}
