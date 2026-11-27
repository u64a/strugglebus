using System.Windows.Input;

namespace StruggleBusMonitor;

internal enum NavPage { Monitor, Humans, Hosts, Admin, Settings }

/// <summary>Which parts of the window are showing for a page.</summary>
internal sealed record PageLayout(bool Settings, bool Enrollment, bool Workspace, bool Monitor, bool Humans, bool Admin, bool Hosts = false);

internal enum ShortcutAction { None, OpenQuickFind, CloseQuickFind }

/// <summary>Pure navigation decisions, kept apart from the window so they can be tested.</summary>
internal static class NavigationLogic
{
    /// <summary>
    /// Settings is available to everyone. The other pages live in the workspace, which an
    /// unenrolled PC does not see: it gets the enrollment panel instead.
    /// </summary>
    public static PageLayout Layout(NavPage page, bool enrolled)
    {
        var settings = page == NavPage.Settings;
        return new PageLayout(
            Settings: settings,
            Enrollment: !settings && !enrolled,
            Workspace: !settings && enrolled,
            Monitor: page == NavPage.Monitor,
            Humans: page == NavPage.Humans,
            Admin: page == NavPage.Admin,
            Hosts: page == NavPage.Hosts);
    }

    /// <summary>Ctrl+K toggles quick find on an enrolled PC; Escape closes it.</summary>
    public static ShortcutAction Shortcut(Key key, ModifierKeys modifiers, bool enrolled, bool quickFindOpen)
    {
        if (key == Key.K && modifiers == ModifierKeys.Control && enrolled)
            return quickFindOpen ? ShortcutAction.CloseQuickFind : ShortcutAction.OpenQuickFind;
        return key == Key.Escape && quickFindOpen ? ShortcutAction.CloseQuickFind : ShortcutAction.None;
    }
}
