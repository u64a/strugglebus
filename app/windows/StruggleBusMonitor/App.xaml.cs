using System.Windows;
using Velopack;

namespace StruggleBusMonitor;

public partial class App : Application
{
    [STAThread]
    public static void Main(string[] args)
    {
        // Must run before any WPF startup: the installer and updater re-launch the app with hook arguments.
        // A downloaded update is only installed at startup when automatic updates are on.
        VelopackApp.Build().SetAutoApplyOnStartup(AppSettings.Load().AutoUpdate).Run();

        var app = new App();
        app.InitializeComponent();
        app.Run();
    }
}
