using System.IO;
using System.Windows;

namespace StruggleBusMonitor;

/// <summary>Admin, Worker hosts: publishing a fleet document that was signed with one of the site's hardware keys.</summary>
public partial class MainWindow
{
    internal async void FleetPublish_Click(object sender, RoutedEventArgs e) => await RunBusy(PublishSignedFleetAsync, sender);

    internal async void SignerAdd_Click(object sender, RoutedEventArgs e) => await RunBusy(AddSignerAsync, sender);

    /// <summary>
    /// Adds a hardware key to the site's signers from its public file, and keeps the set at once:
    /// the operator does not write or maintain signer lines by hand.
    /// </summary>
    private async Task AddSignerAsync()
    {
        if (_platform.PickPublicKeyFile(this) is { } path) await AddSignerFromAsync(path);
    }

    internal async void FoundKeyAdd_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<FoundKey>(sender) is { } found) await RunBusy(() => AddSignerFromAsync(found.Path), sender);
    }

    /// <summary>Lists the hardware keys found on this PC that are not site signers yet.</summary>
    private void ShowFoundKeys()
    {
        var found = SiteSignersLogic.Found(_platform.PublicKeyFiles(), HostSigners.Text);
        FoundKeysList.ItemsSource = found;
        FoundKeysText.Text = SiteSignersLogic.FoundText(found.Count, FleetPublishLogic.Signers(HostSigners.Text).Count);
    }

    /// <summary>The one path every key takes to become a site signer, found or chosen: the fingerprint, the question, Windows Hello.</summary>
    private async Task AddSignerFromAsync(string path)
    {
        var chosen = new FileInfo(path).Length <= SshSignature.MaxLength ? await File.ReadAllTextAsync(path) : string.Empty;
        var next = SiteSignersLogic.Add(HostSigners.Text, SiteSignersLogic.LineFor(chosen));
        var signer = FleetPublishLogic.Signers(next)[^1];
        if (!_platform.Confirm(this, SiteSignersLogic.AddReview(signer, Path.GetFileName(path)), "Add a site signer")) return;
        await RequireHelloAsync(SiteSignersLogic.AddHelloPrompt(signer));
        RememberKeyFile(signer, path);
        KeepSigners(next);
    }

    /// <summary>Notes where the key's own file is, when it sits beside the public file, so the app can ask that key to sign.</summary>
    private void RememberKeyFile(SiteSigner signer, string publicKeyPath)
    {
        if (FleetSignLogic.KeyFileBeside(publicKeyPath, _platform.FileExists) is not { } keyFile) return;
        _settings.SignerKeyFiles[signer.KeyBase64] = keyFile;
        _settings.Save();
    }

    internal void SignerUse_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<SiteSigner>(sender) is not { } signer) return;
        _settings.SigningKey = signer.KeyBase64;
        _settings.Save();
        ShowSigningKey();
    }

    /// <summary>Says which key the app will ask to sign, or why it cannot ask any.</summary>
    private void ShowSigningKey()
    {
        var key = FleetSignLogic.KeyToUse(FleetPublishLogic.Signers(HostSigners.Text), _settings.SignerKeyFiles, _settings.SigningKey, _platform.FileExists);
        SigningKeyText.Text = FleetSignLogic.SigningKeyText(key, _platform.HardwareSigningTool is not null);
    }

    /// <summary>Offers the keys an earlier version kept unprotected, when there are any not yet confirmed.</summary>
    private void ShowEarlierSigners()
    {
        var earlier = SiteSignersLogic.Earlier(_settings.HostSigners, HostSigners.Text);
        SignersEarlierButton.Content = SiteSignersLogic.EarlierButton(earlier.Count);
        SignersEarlierButton.Visibility = VisibleWhen(earlier.Count > 0);
    }

    internal async void SignersEarlier_Click(object sender, RoutedEventArgs e) => await RunBusy(KeepEarlierSignersAsync, sender);

    /// <summary>The same path as adding a key: the fingerprints, the question, Windows Hello, and only then are they kept.</summary>
    private async Task KeepEarlierSignersAsync()
    {
        var earlier = SiteSignersLogic.Earlier(_settings.HostSigners, HostSigners.Text);
        if (earlier.Count == 0 || !_platform.Confirm(this, SiteSignersLogic.EarlierReview(earlier), "Keep earlier site signers")) return;
        await RequireHelloAsync(SiteSignersLogic.EarlierHelloPrompt(earlier.Count));
        KeepSigners(SiteSignersLogic.With(HostSigners.Text, earlier));
        _settings.HostSigners = string.Empty;
        _settings.Save();
        ShowEarlierSigners();
    }

    internal async void SignerRemove_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<SiteSigner>(sender) is { } signer) await RunBusy(() => RemoveSignerAsync(signer), sender);
    }

    private async Task RemoveSignerAsync(SiteSigner signer)
    {
        var next = SiteSignersLogic.Remove(HostSigners.Text, signer.KeyBase64);
        if (!_platform.Confirm(this, SiteSignersLogic.RemoveReview(signer), "Remove a site signer")) return;
        await RequireHelloAsync(SiteSignersLogic.RemoveHelloPrompt(signer));
        if (_settings.SignerKeyFiles.Remove(signer.KeyBase64)) _settings.Save();
        KeepSigners(next);
    }

    /// <summary>Shows the set and stores it, protected for this Windows account.</summary>
    private void KeepSigners(string lines)
    {
        HostSigners.Text = lines;
        SiteSignersStore.Save(lines);
    }

    internal void HostSigners_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        SignersSummary.Text = SiteSignersLogic.Summary(HostSigners.Text);
        SignersList.ItemsSource = FleetPublishLogic.Signers(HostSigners.Text);
        ShowSigningKey();
        ShowFoundKeys();
    }

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

    /// <summary>The document and the signature beside it, checked against the site signers this PC holds (Admin, Security).</summary>
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
