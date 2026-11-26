using System.Windows;
using Velopack;

namespace StruggleBusMonitor;

public partial class App : Application
{
    [STAThread]
    public static void Main(string[] args)
    {
        // Must run before any WPF startup: the installer and updater re-launch the app with hook arguments.
        // The framework is told not to install a downloaded update by itself: the app does it
        // just below, after checking the update's signatures, and only when automatic updates are on.
        VelopackApp.Build().SetAutoApplyOnStartup(false).Run();
        ApplyPendingUpdate(AppSettings.Load());

        var app = new App();
        app.InitializeComponent();
        app.Run();
    }

    private static void ApplyPendingUpdate(AppSettings settings) =>
        ApplyPendingUpdate(settings, new AppUpdater(), settings.Save);

    /// <summary>With automatic updates on, installs an update that an earlier run downloaded.</summary>
    internal static void ApplyPendingUpdate(AppSettings settings, AppUpdater updater, Action save)
    {
        if (!settings.AutoUpdate) return;
        updater.ApplyPendingAtStartup(settings.StartupUpdateAttempt, version =>
        {
            settings.StartupUpdateAttempt = version;
            save();
        });
    }
}
