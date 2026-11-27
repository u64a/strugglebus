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
        // Uninstalling also takes the app out of the programs Windows starts at sign-in.
        VelopackApp.Build().SetAutoApplyOnStartup(false).OnBeforeUninstallFastCallback(_ => SignInStart.Set(false)).Run();
        ApplyPendingUpdate(AppSettings.Load(), TrayArguments(args));

        var app = new App();
        app.InitializeComponent();
        app.Run();
    }

    /// <summary>An app started in the tray comes back in the tray after it updates itself.</summary>
    internal static string[] TrayArguments(IEnumerable<string> arguments) =>
        arguments.Contains(TrayLogic.StartArgument, StringComparer.OrdinalIgnoreCase) ? [TrayLogic.StartArgument] : [];

    private static void ApplyPendingUpdate(AppSettings settings, string[] restartArguments) =>
        ApplyPendingUpdate(settings, new AppUpdater(), settings.Save, restartArguments);

    /// <summary>With automatic updates on, installs an update that an earlier run downloaded.</summary>
    internal static void ApplyPendingUpdate(AppSettings settings, AppUpdater updater, Action save, params string[] restartArguments)
    {
        if (!settings.AutoUpdate) return;
        updater.ApplyPendingAtStartup(settings.StartupUpdateAttempt, version =>
        {
            settings.StartupUpdateAttempt = version;
            save();
        }, restartArguments);
    }
}
