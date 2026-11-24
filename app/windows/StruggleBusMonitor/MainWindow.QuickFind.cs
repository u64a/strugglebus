using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace StruggleBusMonitor;

/// <summary>Ctrl+K quick find across agents and the loaded messages. The rules are in <see cref="QuickFindLogic"/>.</summary>
public partial class MainWindow
{
    private readonly ObservableCollection<QuickFindResult> _findResults = [];

    private void QuickFindButton_Click(object sender, RoutedEventArgs e) => OpenQuickFind();

    private void OpenQuickFind()
    {
        QuickFindList.ItemsSource ??= _findResults;
        CloseMentionPopup();
        QuickFindOverlay.Visibility = Visibility.Visible;
        QuickFindBox.Clear();
        FindScopeAll.IsChecked = true;
        RefreshQuickFind();
        QuickFindBox.Focus();
    }

    private void CloseQuickFind()
    {
        if (QuickFindOverlay is not null) QuickFindOverlay.Visibility = Visibility.Collapsed;
    }

    private void QuickFindScrim_MouseDown(object sender, MouseButtonEventArgs e) => CloseQuickFind();

    private void QuickFindBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_ready) RefreshQuickFind();
    }

    private void FindScope_Checked(object sender, RoutedEventArgs e)
    {
        if (_ready && QuickFindOverlay.Visibility == Visibility.Visible) RefreshQuickFind();
    }

    private RadioButton[] FindScopes => [FindScopeAll, FindScopeAgents, FindScopeMessages];

    private QuickFindScope SelectedFindScope() =>
        FindScopeAgents.IsChecked == true ? QuickFindScope.Agents
        : FindScopeMessages.IsChecked == true ? QuickFindScope.Messages
        : QuickFindScope.All;

    private void RefreshQuickFind()
    {
        var loaded = _activity.Select(entry => entry.Message).Concat(_pendingActivity);
        var outcome = QuickFindLogic.Search(QuickFindBox.Text, SelectedFindScope(), _agentModels, loaded, _historySupported, DateTimeOffset.Now);
        _findResults.Clear();
        foreach (var result in outcome.Results) _findResults.Add(result);
        ShowFindResults(outcome.EmptyText);
    }

    private void ShowFindResults(string emptyText)
    {
        QuickFindList.Visibility = VisibleWhen(_findResults.Count > 0);
        QuickFindEmpty.Visibility = VisibleWhen(_findResults.Count == 0);
        QuickFindEmpty.Text = emptyText;
        if (_findResults.Count > 0) QuickFindList.SelectedIndex = 0;
    }

    private async Task SearchHistoryAsync(string text)
    {
        _findResults.Clear();
        ShowFindResults(QuickFindLogic.Searching(text));
        try
        {
            var now = DateTimeOffset.Now;
            var hits = await _api.SearchAsync(text, QuickFindLogic.MaximumMessages, CancellationToken.None);
            if (QuickFindLogic.IsStale(QuickFindOverlay.Visibility == Visibility.Visible, QuickFindBox.Text, text)) return;
            foreach (var message in hits) _findResults.Add(QuickFindLogic.MessageRow(message, text, now));
            ShowFindResults(QuickFindLogic.NothingOnBus(text));
        }
        catch (Exception error)
        {
            ShowFindResults(QuickFindLogic.SearchFailed(error.Message));
        }
    }

    private void QuickFindBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        var action = QuickFindLogic.KeyAction(e.Key);
        if (action == QuickFindKeyAction.None) return;
        e.Handled = true;
        RunFindAction(action);
    }

    private void RunFindAction(QuickFindKeyAction action)
    {
        switch (action)
        {
            case QuickFindKeyAction.Next:
                MoveFindSelection(1);
                break;
            case QuickFindKeyAction.Previous:
                MoveFindSelection(-1);
                break;
            case QuickFindKeyAction.Open:
                if (QuickFindList.SelectedItem is QuickFindResult result) OpenFindResult(result);
                break;
            default:
                ChangeFindScope(Keyboard.Modifiers.HasFlag(ModifierKeys.Shift));
                break;
        }
    }

    private void ChangeFindScope(bool backwards)
    {
        var scopes = FindScopes;
        var current = Array.FindIndex(scopes, scope => scope.IsChecked == true);
        scopes[QuickFindLogic.NextScopeIndex(current, backwards, scopes.Length)].IsChecked = true;
    }

    private void MoveFindSelection(int step)
    {
        if (_findResults.Count == 0) return;
        var index = QuickFindLogic.MoveSelection(QuickFindList.SelectedIndex, step, _findResults.Count);
        QuickFindList.SelectedIndex = index;
        QuickFindList.ScrollIntoView(_findResults[index]);
    }

    private void QuickFindList_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (ClickedRow<QuickFindResult>(QuickFindList, e.OriginalSource) is not { } result) return;
        e.Handled = true;
        OpenFindResult(result);
    }

    private void OpenFindResult(QuickFindResult result)
    {
        if (result.HistoryQuery is { } historyQuery)
        {
            _ = SearchHistoryAsync(historyQuery);
            return;
        }
        CloseQuickFind();
        if (result.Message is { } message) JumpToMessage(message);
        else if (result.Agent is { } agent) ShowAgentFromFind(agent);
    }

    private void ShowAgentFromFind(BusAgent agent)
    {
        MonitorNav.IsChecked = true;
        AgentFilterBox.Clear();
        SelectAgent(agent.Name);
        if (AgentList.SelectedItem is { } selected) AgentList.ScrollIntoView(selected);
    }
}
