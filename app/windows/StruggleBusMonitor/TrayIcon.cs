using Microsoft.Win32;
using Forms = System.Windows.Forms;

namespace StruggleBusMonitor;

/// <summary>The real tray icon: Open on a click, and a menu with Open and Quit.</summary>
internal sealed class TrayIcon : ITrayIcon
{
    private const int NoticeMilliseconds = 6000;
    private readonly Forms.NotifyIcon _icon;

    public TrayIcon(Action open, Action quit)
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open", null, (_, _) => open());
        menu.Items.Add("Quit", null, (_, _) => quit());
        _icon = new Forms.NotifyIcon
        {
            Icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath!),
            ContextMenuStrip = menu,
            Text = TrayLogic.Tooltip(string.Empty, 0),
            Visible = true
        };
        _icon.MouseClick += (_, click) => OpenOnLeftClick(click.Button, open);
    }

    private static void OpenOnLeftClick(Forms.MouseButtons button, Action open)
    {
        if (button == Forms.MouseButtons.Left) open();
    }

    public string Tooltip { set => _icon.Text = value; }

    public void Notify(string text) => _icon.ShowBalloonTip(NoticeMilliseconds, "StruggleBus Monitor", text, Forms.ToolTipIcon.Info);

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.ContextMenuStrip?.Dispose();
        _icon.Dispose();
    }
}

/// <summary>This app's entry among the programs Windows starts when this user signs in.</summary>
internal static class SignInStart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

    public static bool IsOn
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(TrayLogic.RunEntryName) is string;
        }
    }

    public static void Set(bool on)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey);
        if (on) key.SetValue(TrayLogic.RunEntryName, TrayLogic.RunCommand(Environment.ProcessPath!));
        else key.DeleteValue(TrayLogic.RunEntryName, throwOnMissingValue: false);
    }
}
