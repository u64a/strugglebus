using System.IO;
using System.Windows;

namespace StruggleBusMonitor;

/// <summary>Admin, Worker hosts: publishing a fleet document that was signed with one of the site's hardware keys.</summary>
public partial class MainWindow
{
    internal async void FleetPublish_Click(object sender, RoutedEventArgs e) => await RunBusy(PublishSignedFleetAsync, sender);

    /// <summary>
    /// Every check comes before the question, the question before Windows Hello, and Hello before
    /// the bus is asked to store anything: a document the hosts would refuse must not spend a
    /// serial. See <see cref="FleetPublishLogic"/>.
    /// </summary>
    private async Task PublishSignedFleetAsync()
    {
        if (_api.Session is null) return;
        if (!_api.HasOperatorGrant()) throw new InvalidOperationException(FleetPublishLogic.NeedsOperator);
        if (_platform.PickFleetFile(this) is not { } path) return;

        var fleet = await ReadVerifiedFleetAsync(path);
        if (!await ApproveFleetAsync(fleet)) return;

        var published = await _api.PublishSiteDocumentAsync(
            FleetPublishLogic.DocumentName, fleet.Serial, fleet.Body, fleet.Signature, fleet.Signer.Fingerprint,
            FleetPublishLogic.Reason(fleet.Serial), CancellationToken.None);
        FleetResult.Text = FleetPublishLogic.ResultText(fleet, published.StoredAt);
        FleetResultPanel.Visibility = Visibility.Visible;
    }

    /// <summary>The document, once its signature has verified for its exact bytes.</summary>
    private async Task<SignedFleet> ReadVerifiedFleetAsync(string path)
    {
        var fleet = await ReadSignedFleetAsync(path);
        var verdict = await _platform.VerifySshSignatureAsync(fleet.Body, fleet.Signature, fleet.Signer.Line, fleet.Signer.Principal, FleetPublishLogic.Namespace);
        return FleetPublishLogic.VerdictProblem(verdict) is { } problem ? throw new InvalidOperationException(problem) : fleet;
    }

    /// <summary>Checks the serial against the bus, asks the operator, then Windows Hello. False when the operator says no.</summary>
    private async Task<bool> ApproveFleetAsync(SignedFleet fleet)
    {
        var stored = (await _api.GetSiteDocumentAsync(FleetPublishLogic.DocumentName, CancellationToken.None))?.Serial;
        if (FleetPublishLogic.SerialProblem(fleet.Serial, stored) is { } stale) throw new InvalidOperationException(stale);
        var question = FleetPublishLogic.ConfirmText(fleet, stored) + ComposedNote(fleet);
        if (!_platform.Confirm(this, question, "Publish the fleet")) return false;
        await RequireHelloAsync(FleetPublishLogic.HelloPrompt(fleet.Serial));
        return true;
    }

    /// <summary>Says so when the document being published is the one this app composed in this run.</summary>
    private string ComposedNote(SignedFleet fleet) =>
        _composedFleet is { } composed && composed.AsSpan().SequenceEqual(fleet.Body) ? "\n\n" + FleetJoinLogic.ComposedNote(_composedFor!) : string.Empty;

    /// <summary>The document and the signature beside it, checked against the signer lines on this PC's Add a host form.</summary>
    private async Task<SignedFleet> ReadSignedFleetAsync(string path)
    {
        var signaturePath = path + ".sig";
        if (!File.Exists(signaturePath))
        {
            throw new InvalidOperationException($"No signature was found. It must be beside the document, named {Path.GetFileName(signaturePath)}.");
        }

        var body = await File.ReadAllBytesAsync(path);
        var signature = new FileInfo(signaturePath).Length <= SshSignature.MaxLength ? await File.ReadAllTextAsync(signaturePath) : null;
        return FleetPublishLogic.Check(body, signature, FleetPublishLogic.Signers(HostSigners.Text));
    }
}
