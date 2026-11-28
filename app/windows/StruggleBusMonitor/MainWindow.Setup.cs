using System.Windows;

namespace StruggleBusMonitor;

/// <summary>Admin: the "Set up this site" checklist, and setting up a new hardware key on Security.</summary>
public partial class MainWindow
{
    /// <summary>What the last reading of the fleet on the bus showed. Null until it has been read, or when it could not be read strictly.</summary>
    private (bool Held, int Hosts, int Agents)? _setupFleet;

    /// <summary>Reads the fleet once for the checklist, when Admin opens before any tab has loaded it.</summary>
    private async Task LoadSetupAsync()
    {
        if (_api.Session is null || _setupFleet is not null) return;
        var (held, listed) = await ListedFleetAsync();
        NoteFleetForSetup(held, listed);
    }

    private void NoteFleetForSetup(bool held, IReadOnlyList<FleetAgent> listed)
    {
        var rows = FleetAccessLogic.Rows(listed);
        _setupFleet = _fleetUnreadable ? null : (held, rows.Count(row => row.Kind == "host"), rows.Count(row => row.Kind == "coordinator"));
        ShowSetup();
    }

    /// <summary>Shows the checklist while any step is left, and hides it when the fleet cannot be read or all are done.</summary>
    private void ShowSetup()
    {
        if (_setupFleet is not { } fleet)
        {
            SetupPanel.Visibility = Visibility.Collapsed;
            return;
        }

        var facts = new SetupFacts(
            FleetPublishLogic.Signers(HostSigners.Text).Count, AddHostLogic.Lines(_settings.HostRemotes).Count > 0,
            fleet.Held, fleet.Hosts, fleet.Agents);
        var items = SetupChecklistLogic.Items(facts);
        var done = SetupChecklistLogic.AllDone(items);
        SetupPanel.Visibility = VisibleWhen(!done);
        SetupList.ItemsSource = items;
        SetupText.Text = done ? string.Empty : SetupChecklistLogic.Summary(items);
    }

    internal void SetupGo_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<SetupItem>(sender) is not { } item) return;
        var tab = item.Tab switch
        {
            SetupChecklistLogic.Security => AdminTabSecurity,
            SetupChecklistLogic.AddHost => AdminTabAddHost,
            _ => AdminTabFleet
        };
        tab.IsChecked = true;
    }

    internal async void NewKey_Click(object sender, RoutedEventArgs e) => await RunBusy(SetUpNewKeyAsync, sender);

    /// <summary>
    /// Makes a new key on the security key that is plugged in, then takes it down the same path
    /// as any other key: its fingerprint, the question, Windows Hello. A key the operator then
    /// declines stays on the security key and shows among the keys found on this PC.
    /// </summary>
    private async Task SetUpNewKeyAsync()
    {
        var name = NewKeyName.Text.Trim();
        if (NewKeyLogic.NameProblem(name) is { } problem) throw new InvalidOperationException(problem);
        if (_platform.HardwareSigningTool is not { } tool) throw new InvalidOperationException(NewKeyLogic.NoTool);

        var publicFile = await MakeKeyAsync(tool, name);
        NewKeyName.Clear();
        try
        {
            await AddSignerFromAsync(publicFile, NewKeyLogic.Review);
        }
        finally
        {
            ShowFoundKeys();
        }
    }

    /// <summary>Asks the tool for the key while the screen says what Windows is waiting for.</summary>
    private async Task<string> MakeKeyAsync(string tool, string name)
    {
        NewKeyText.Text = NewKeyLogic.TouchText;
        try
        {
            return await _platform.CreateHardwareKeyAsync(tool, name);
        }
        catch (SshSigningException refused)
        {
            throw new InvalidOperationException(NewKeyLogic.Failed(refused.Message));
        }
        finally
        {
            NewKeyText.Text = string.Empty;
        }
    }
}
