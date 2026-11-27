using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace StruggleBusMonitor;

/// <summary>
/// Humans page: the #humans conversation, the composer with @mention completion, and the waiting
/// list. The rules live in <see cref="HumansThread"/> and <see cref="HumansPageLogic"/>; this file
/// only moves their answers onto the controls.
/// </summary>
public partial class MainWindow
{
    private readonly HumansThread _humansThread = new();
    private readonly ObservableCollection<HumansEntry> _humans = [];
    private readonly Dictionary<long, HumansEntry> _humansEntries = [];
    private readonly Dictionary<OutgoingPost, HumansEntry> _outboxEntries = [];
    private readonly ObservableCollection<WaitingEntry> _waiting = [];
    private readonly ObservableCollection<MentionRow> _mentionRows = [];
    private ScrollViewer? _humansScroll;
    private BusMessage? _humansReplyTarget;
    private int _humansNewBelow;
    private int _mentionDismissedAt = -1;
    private bool _updatingWaitingSelection;

    private void InitializeHumans()
    {
        HumansList.ItemsSource = _humans;
        WaitingList.ItemsSource = _waiting;
        MentionList.ItemsSource = _mentionRows;
        UpdateHumansSummary();
    }

    /// <summary>The row a button inside an item template was made for.</summary>
    private static T? TagOf<T>(object sender) where T : class => (sender as FrameworkElement)?.Tag as T;

    private bool HumansVisible => HumansPage.Visibility == Visibility.Visible && WorkspacePanel.Visibility == Visibility.Visible;

    private bool HumansAtBottom =>
        (_humansScroll ??= FindScrollViewer(HumansList)) is not { } viewer || viewer.VerticalOffset >= viewer.ScrollableHeight - 2;

    private void OnHumansPageShown()
    {
        MarkHumansRead();
        UpdateHumansSummary();
        ScrollHumansToEnd();
        HumansComposer.Focus();
    }

    private void RecordHumansMessages(IEnumerable<BusMessage> messages)
    {
        var wasAtBottom = HumansAtBottom;
        var change = _humansThread.Record(messages);
        ShowHumansRows(change);
        if (change.Fresh == 0) return;

        ShowHumansArrival(HumansPageLogic.Arrival(HumansVisible, wasAtBottom), change.Fresh);
        if (change.FreshFromAgents > 0 && _ready) FlashTaskbar();
        UpdateHumansSummary();
    }

    /// <summary>Adds a row for each new message and drops the rows of messages that rolled off the start.</summary>
    private void ShowHumansRows(HumansChange change)
    {
        var now = DateTimeOffset.Now;
        foreach (var added in change.Added)
        {
            var entry = HumansEntry.ForMessage(added.Message, added.Parent, now);
            _humansEntries[added.Message.Seq] = entry;
            _humans.Insert(HumansPageLogic.InsertIndex(_humans, _outboxEntries.Count, added.Message.Seq), entry);
        }
        foreach (var sequence in change.Trimmed)
        {
            if (_humansEntries.Remove(sequence, out var stale)) _humans.Remove(stale);
        }
    }

    private void ShowHumansArrival(HumansArrival arrival, int count)
    {
        if (arrival == HumansArrival.FollowToEnd)
        {
            MarkHumansRead();
            ScrollHumansToEnd();
        }
        else if (arrival == HumansArrival.CountBelow)
        {
            _humansNewBelow += count;
            UpdateHumansNewBar();
        }
    }

    private void MarkHumansRead()
    {
        _humansThread.MarkRead();
        _humansNewBelow = 0;
        UpdateHumansNewBar();
        UpdateHumansBadge();
    }

    private void UpdateHumansBadge()
    {
        var unread = HumansVisible && HumansAtBottom ? 0 : _humansThread.Unread;
        HumansBadge.Visibility = VisibleWhen(unread > 0);
        HumansBadgeText.Text = HumansPageLogic.BadgeText(unread);
    }

    private void UpdateHumansNewBar()
    {
        HumansNewBar.Visibility = VisibleWhen(_humansNewBelow > 0);
        HumansNewText.Text = HumansPageLogic.NewBelowText(_humansNewBelow);
    }

    private void UpdateHumansSummary()
    {
        HumansCountText.Text = $"{_humansThread.Count} messages";
        HumansEmptyText.Visibility = VisibleWhen(_humans.Count == 0);
        HumansNotice.Text = HumansPageLogic.Notice(_api.HasOperatorGrant());
        UpdateWaitingList();
        UpdateHumansBadge();
    }

    private void UpdateWaitingList()
    {
        var waiting = FeedLogic.WaitingOnOperator(_humansThread.Messages, _settings.ClearedWaiting.ToHashSet());
        if (HumansPageLogic.WaitingChanged(waiting, _waiting))
        {
            var now = DateTimeOffset.Now;
            _updatingWaitingSelection = true;
            _waiting.Clear();
            foreach (var message in waiting) _waiting.Add(new WaitingEntry(message, now));
            _updatingWaitingSelection = false;
        }
        WaitingCountText.Text = _waiting.Count.ToString();
        UpdateTrayTooltip();
        WaitingClearAll.Visibility = VisibleWhen(_waiting.Count > 1);
        WaitingHint.Text = HumansPageLogic.HintForWaiting(_waiting.Count);
    }

    private void ScrollHumansToEnd()
    {
        if (_humans.Count == 0) return;
        Dispatcher.BeginInvoke(ScrollHumansToLastRow, System.Windows.Threading.DispatcherPriority.Background);
    }

    private void ScrollHumansToLastRow()
    {
        if (_humans.Count > 0) HumansList.ScrollIntoView(_humans[^1]);
    }

    private void HumansList_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        var badgeShown = HumansBadge.Visibility == Visibility.Visible;
        if (HumansPageLogic.ScrollReadsConversation(e.VerticalChange, HumansVisible, HumansAtBottom, _humansNewBelow, badgeShown))
            MarkHumansRead();
    }

    private void HumansJump_Click(object sender, RoutedEventArgs e)
    {
        MarkHumansRead();
        ScrollHumansToEnd();
    }

    private void WaitingList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_updatingWaitingSelection || WaitingList.SelectedItem is not WaitingEntry waiting) return;
        _updatingWaitingSelection = true;
        WaitingList.SelectedItem = null;
        _updatingWaitingSelection = false;
        if (!_humansEntries.TryGetValue(waiting.Message.Seq, out var entry)) return;
        HumansList.SelectedItem = entry;
        HumansList.ScrollIntoView(entry);
        StartReply(waiting.Message);
    }

    private void WaitingClear_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<WaitingEntry>(sender) is { } waiting) ClearWaiting([waiting.Message.Seq]);
    }

    private void WaitingClearAll_Click(object sender, RoutedEventArgs e) =>
        ClearWaiting(_waiting.Select(entry => entry.Message.Seq).ToList());

    private void ClearWaiting(IReadOnlyCollection<long> sequences)
    {
        _settings.ClearWaiting(sequences);
        _settings.Save();
        UpdateHumansSummary();
    }

    // ---- Composer ----------------------------------------------------------------------------

    private void HumansComposer_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready) return;
        HumansCharCount.Text = $"{HumansComposer.Text.Length} / {HumansLogic.MaxBodyChars}";
        RefreshMentionPopup();
    }

    private void HumansComposer_SelectionChanged(object sender, RoutedEventArgs e)
    {
        if (_ready) RefreshMentionPopup();
    }

    private void HumansComposer_LostKeyboardFocus(object sender, KeyboardFocusChangedEventArgs e) => CloseMentionPopup();

    private void HumansComposer_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        var action = HumansPageLogic.KeyAction(e.Key, Keyboard.Modifiers.HasFlag(ModifierKeys.Shift), MentionPopup.IsOpen);
        if (action == ComposerKeyAction.None) return;
        e.Handled = true;
        RunComposerAction(action);
    }

    private void RunComposerAction(ComposerKeyAction action)
    {
        switch (action)
        {
            case ComposerKeyAction.MentionNext:
                MoveMentionSelection(1);
                break;
            case ComposerKeyAction.MentionPrevious:
                MoveMentionSelection(-1);
                break;
            case ComposerKeyAction.MentionAccept:
                if (MentionList.SelectedItem is MentionRow row) InsertMention(row);
                break;
            case ComposerKeyAction.MentionDismiss:
                _mentionDismissedAt = HumansPageLogic.MentionStart(HumansComposer.Text, HumansComposer.CaretIndex);
                CloseMentionPopup();
                break;
            default:
                SendHumansMessage();
                break;
        }
    }

    private void RefreshMentionPopup()
    {
        var plan = HumansPageLogic.PlanMentions(
            HumansComposer.IsKeyboardFocused,
            HumansComposer.Text,
            HumansComposer.CaretIndex,
            _mentionDismissedAt,
            _agentModels,
            (MentionList.SelectedItem as MentionRow)?.Option.Insert,
            DateTimeOffset.Now);
        _mentionDismissedAt = plan.DismissedAt;
        if (plan.Options is { } options)
        {
            _mentionRows.Clear();
            foreach (var option in options) _mentionRows.Add(new MentionRow(option));
        }
        if (!plan.Open)
        {
            CloseMentionPopup();
            return;
        }
        MentionList.SelectedIndex = plan.SelectedIndex;
        MentionHeader.Text = plan.Header;
        MentionPopup.IsOpen = true;
    }

    private void CloseMentionPopup()
    {
        if (MentionPopup is not null) MentionPopup.IsOpen = false;
    }

    private void MoveMentionSelection(int step)
    {
        if (_mentionRows.Count == 0) return;
        var index = HumansPageLogic.WrapSelection(MentionList.SelectedIndex, step, _mentionRows.Count);
        MentionList.SelectedIndex = index;
        MentionList.ScrollIntoView(_mentionRows[index]);
    }

    /// <summary>The data row of the list item that was clicked, if the click landed on one.</summary>
    private static T? ClickedRow<T>(ItemsControl list, object source) where T : class =>
        source is DependencyObject element && ItemsControl.ContainerFromElement(list, element) is ListBoxItem item
            ? item.DataContext as T
            : null;

    private void MentionList_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        // Handled on the way down so the composer keeps keyboard focus.
        e.Handled = true;
        if (ClickedRow<MentionRow>(MentionList, e.OriginalSource) is { } row) InsertMention(row);
    }

    private void InsertMention(MentionRow row)
    {
        if (HumansPageLogic.InsertMention(HumansComposer.Text, HumansComposer.CaretIndex, row.Option.Insert) is not { } edit) return;
        HumansComposer.Text = edit.Text;
        HumansComposer.CaretIndex = edit.Caret;
        CloseMentionPopup();
    }

    private void HumansSend_Click(object sender, RoutedEventArgs e) => SendHumansMessage();

    private void SendHumansMessage()
    {
        if (string.IsNullOrWhiteSpace(HumansComposer.Text)) return;
        var expanded = FeedLogic.ExpandEveryone(HumansComposer.Text, _agentModels, DateTimeOffset.Now);
        var body = HumansLogic.NormalizeBody(expanded);
        if (body is null)
        {
            ShowNotice($"Messages are limited to {HumansLogic.MaxBodyChars} characters once @everyone is expanded into agent names.");
            return;
        }
        if (!_api.HasOperatorGrant())
        {
            ShowNotice("Save operator access on the Admin page once before posting to #humans.", "Open Admin", OpenAdminPage);
            return;
        }

        var post = new OutgoingPost
        {
            RequestId = Guid.NewGuid().ToString("D"),
            Body = body,
            Kind = SelectedHumansKind(),
            ReplyTo = _humansReplyTarget
        };
        HumansComposer.Clear();
        SetHumansReplyTarget(null);
        HumansKindChat.IsChecked = true;
        _ = DeliverHumansPostAsync(post);
    }

    private void OpenAdminPage() => AdminNav.IsChecked = true;

    private void ShowOutgoing(OutgoingPost post)
    {
        var entry = HumansEntry.ForOutgoing(post);
        if (_outboxEntries.TryGetValue(post, out var existing) && _humans.IndexOf(existing) is >= 0 and var index)
            _humans[index] = entry;
        else
            _humans.Add(entry);
        _outboxEntries[post] = entry;
        UpdateHumansSummary();
    }

    private void RemoveOutgoing(OutgoingPost post)
    {
        if (_outboxEntries.Remove(post, out var entry)) _humans.Remove(entry);
        UpdateHumansSummary();
    }

    private async Task DeliverHumansPostAsync(OutgoingPost post)
    {
        post.Status = OutgoingStatus.Sending;
        post.Error = null;
        ShowOutgoing(post);
        ScrollHumansToEnd();
        try
        {
            var message = await _api.PostHumanMessageAsync(post.RequestId, post.Body, post.Kind, post.ReplyTo?.Seq, CancellationToken.None);
            RemoveOutgoing(post);
            AddActivityMessage(message);
            MarkHumansRead();
            ScrollHumansToEnd();
        }
        catch (Exception error)
        {
            ShowPostFailure(post, HumansLogic.ClassifyFailure(error));
        }
    }

    private void ShowPostFailure(OutgoingPost post, PostFailure failure)
    {
        if (failure.ClearGrant)
        {
            BusApi.GrantStore.Clear();
            UpdateGrantStatus();
        }
        post.Status = OutgoingStatus.Failed;
        post.Error = failure.Detail;
        post.Retryable = failure.Retryable;
        ShowOutgoing(post);
    }

    private HumanMessageKind SelectedHumansKind() =>
        HumansKindQuestion.IsChecked == true ? HumanMessageKind.Question
        : HumansKindAnswer.IsChecked == true ? HumanMessageKind.Answer
        : HumanMessageKind.Chat;

    private void SetHumansReplyTarget(BusMessage? target)
    {
        _humansReplyTarget = target;
        HumansReplyBanner.Visibility = VisibleWhen(target is not null);
        HumansReplyText.Text = HumansPageLogic.ReplyBanner(target);
    }

    private void StartReply(BusMessage target)
    {
        SetHumansReplyTarget(target);
        switch (HumansLogic.DefaultKindForReply(target, SelectedHumansKind()))
        {
            case HumanMessageKind.Answer: HumansKindAnswer.IsChecked = true; break;
            case HumanMessageKind.Question: HumansKindQuestion.IsChecked = true; break;
            default: HumansKindChat.IsChecked = true; break;
        }
        HumansComposer.Focus();
    }

    private void HumansReply_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<HumansEntry>(sender)?.Message is { } target) StartReply(target);
    }

    private void HumansCancelReply_Click(object sender, RoutedEventArgs e) => SetHumansReplyTarget(null);

    private void CopyHumans_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<HumansEntry>(sender)?.Message is { } message) CopyText(message.Body);
    }

    private void HumansRetry_Click(object sender, RoutedEventArgs e)
    {
        if (HumansPageLogic.FailedPost(TagOf<HumansEntry>(sender), retryableOnly: true) is not { } post) return;
        if (!_api.HasOperatorGrant())
        {
            ShowNotice("Save operator access on the Admin page, then retry.", "Open Admin", OpenAdminPage);
            return;
        }
        _ = DeliverHumansPostAsync(post);
    }

    private void HumansDiscard_Click(object sender, RoutedEventArgs e)
    {
        if (HumansPageLogic.FailedPost(TagOf<HumansEntry>(sender), retryableOnly: false) is not { } post) return;
        RemoveOutgoing(post);
        if (string.IsNullOrWhiteSpace(HumansComposer.Text)) HumansComposer.Text = post.Body;
    }

    private void ResetHumans()
    {
        _humansThread.Reset();
        _humansEntries.Clear();
        _outboxEntries.Clear();
        _humans.Clear();
        // Sequence numbers belong to the bus this PC was linked to.
        _settings.ClearedWaiting = [];
        _settings.Save();
        SetHumansReplyTarget(null);
        MarkHumansRead();
        UpdateHumansSummary();
    }
}
