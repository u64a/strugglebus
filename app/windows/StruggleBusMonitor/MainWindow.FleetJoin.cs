using System.IO;
using System.Text;
using System.Windows;

namespace StruggleBusMonitor;

/// <summary>
/// Admin, Worker hosts: step 10 of Add a host. The operator compares the confirmation code, and
/// only on a match is the next fleet document composed and saved for a hardware key to sign.
/// </summary>
public partial class MainWindow
{
    /// <summary>The last document composed in this run and the host it added, so that publishing can say it is the same bytes.</summary>
    private byte[]? _composedFleet;
    private string? _composedFor;

    internal async void HostJoin_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<HostRow>(sender) is { Join: { } join }) await RunBusy(() => JoinFleetAsync(join), sender);
    }

    /// <summary>
    /// The comparison comes first and decides everything: a No never composes, and a Yes composes
    /// from the bus's current document only after that document's own signature has verified.
    /// </summary>
    private async Task JoinFleetAsync(HostJoin join)
    {
        if (!_api.HasOperatorGrant()) throw new InvalidOperationException(AdminFlow.GrantNeeded);
        if (!_platform.Confirm(this, FleetJoinLogic.CompareText(join), FleetJoinLogic.CompareCaption))
        {
            await RefuseHostAsync(join);
            return;
        }

        var current = await ReadCurrentFleetAsync();
        var next = FleetCompose.Next(Encoding.UTF8.GetString(current.Fleet.Body), join.AgentName, join.AgentId, current.BusSerial, ReportedFleetSerials());
        ShowFleetResult(await SaveForSigningAsync(join, current, next) ?? FleetJoinLogic.NothingChanged);
    }

    /// <summary>The bus's current fleet, once its signature has verified against the signer lines this PC holds.</summary>
    private async Task<(SignedFleet Fleet, long BusSerial)> ReadCurrentFleetAsync()
    {
        var stored = await _api.GetSiteDocumentAsync(FleetPublishLogic.DocumentName, CancellationToken.None)
            ?? throw new InvalidOperationException(FleetJoinLogic.NoFleetYet);
        var fleet = FleetPublishLogic.Check(stored.Body, stored.Signature, FleetPublishLogic.Signers(HostSigners.Text));
        var verdict = await _platform.VerifySshSignatureAsync(fleet.Body, fleet.Signature, fleet.Signer.Line, fleet.Signer.Principal, FleetPublishLogic.Namespace);
        return FleetPublishLogic.VerdictProblem(verdict) is { } problem
            ? throw new InvalidOperationException("The fleet the bus holds: " + problem)
            : (fleet, stored.Serial);
    }

    /// <summary>The fleet serial every listed host says it runs.</summary>
    private IEnumerable<long> ReportedFleetSerials() => _adminHosts.Select(row => row.FleetSerial).OfType<long>();

    /// <summary>Shows what will be signed, asks where to save, and saves. Null when the operator stops at either question.</summary>
    private async Task<string?> SaveForSigningAsync(HostJoin join, (SignedFleet Fleet, long BusSerial) current, string next)
    {
        if (!_platform.Confirm(this, FleetJoinLogic.SignText(join, current.BusSerial, current.Fleet.Signer), FleetJoinLogic.SignCaption)) return null;
        if (_platform.PickFleetSavePath(this) is not { } path) return null;

        var bytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false).GetBytes(next);
        await File.WriteAllBytesAsync(path, bytes);
        await File.WriteAllTextAsync(FleetJoinLogic.SignersPath(path), FleetJoinLogic.SignersFile(FleetPublishLogic.Signers(HostSigners.Text)));
        _composedFleet = bytes;
        _composedFor = join.AgentName;
        return FleetJoinLogic.SavedText(path, current.BusSerial + 1, join);
    }

    /// <summary>
    /// After a No: asks whether to shut out whoever redeemed the code. Only a Yes and Windows Hello
    /// revoke the service principal and retire the agent. The fleet is never touched here.
    /// </summary>
    private async Task RefuseHostAsync(HostJoin join)
    {
        if (!_platform.Confirm(this, FleetJoinLogic.NoMatchText(join), FleetJoinLogic.NoMatchCaption))
        {
            ShowFleetResult(FleetJoinLogic.NothingChanged);
            return;
        }

        await RequireHelloAsync(FleetJoinLogic.RetireHelloPrompt(join));
        var reason = FleetJoinLogic.RetireReason(join);
        var revoked = await RevokePrincipalAsync(join, reason);
        var retired = await RetireAgentAsync(join, reason);
        ShowFleetResult(FleetJoinLogic.RetiredText(join, revoked, retired));
        await LoadHostsAsync();
    }

    private async Task<bool> RevokePrincipalAsync(HostJoin join, string reason)
    {
        var principal = join.Principal;
        if (FleetJoinLogic.Offered(principal.Actions, FleetJoinLogic.RevokeAction) is null) return false;
        await _api.ControlServicePrincipalAsync(principal.Id, principal.Name, principal.Version, FleetJoinLogic.RevokeAction, reason, CancellationToken.None);
        return true;
    }

    private async Task<bool> RetireAgentAsync(HostJoin join, string reason)
    {
        var agents = await _api.GetManagedAgentsAsync(includeRetired: false, CancellationToken.None);
        if (agents.FirstOrDefault(candidate => candidate.Id == join.AgentId) is not { } agent) return false;
        if (FleetJoinLogic.Offered(agent.Actions, FleetJoinLogic.RetireAction) is null) return false;
        await _api.ControlAgentAsync(agent.Id, agent.Name, agent.CredentialEpoch, FleetJoinLogic.RetireAction, reason, CancellationToken.None);
        return true;
    }

    private void ShowFleetResult(string text)
    {
        FleetResult.Text = text;
        FleetResultPanel.Visibility = Visibility.Visible;
    }
}
