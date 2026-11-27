using System.Windows;

namespace StruggleBusMonitor;

/// <summary>The About card at the foot of Settings: whose this is, the licence, and where to read more.</summary>
public partial class MainWindow
{
    private void InitializeAbout()
    {
        AboutWhatText.Text = AboutLogic.What;
        AboutOwnerText.Text = AboutLogic.Owner;
        AboutLicenceText.Text = AboutLogic.Licence;
        AboutLinksNote.Text = AboutLogic.LinksNote;
        AboutLinks.ItemsSource = AboutLogic.Links;
    }

    /// <summary>Opens one of the card's own links in the browser. Any other address is ignored.</summary>
    internal void AboutLink_Click(object sender, RoutedEventArgs e)
    {
        if (TagOf<AboutLink>(sender) is not { } link || !AboutLogic.MayOpen(link.Url)) return;
        try { _platform.OpenLink(link.Url); }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            ShowNotice($"Windows could not open a browser. The address is {link.Url}");
        }
    }
}
