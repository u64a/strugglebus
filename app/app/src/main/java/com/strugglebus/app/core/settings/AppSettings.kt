package com.strugglebus.app.core.settings

import android.content.Context
import com.strugglebus.app.ui.theme.ThemePalette
import com.strugglebus.app.ui.theme.Themes
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

enum class ThemeMode { DARK, LIGHT, SYSTEM }

data class ThemeSettings(
    val mode: ThemeMode = ThemeMode.DARK,
    val darkThemeId: String = Themes.DEFAULT_DARK,
    val lightThemeId: String = Themes.DEFAULT_LIGHT,
) {
    fun resolve(systemPrefersLight: Boolean): ThemePalette {
        val light = when (mode) {
            ThemeMode.DARK -> false
            ThemeMode.LIGHT -> true
            ThemeMode.SYSTEM -> systemPrefersLight
        }
        return Themes.find(if (light) lightThemeId else darkThemeId, light)
    }
}

/** Appearance preferences. Nothing here is sensitive, so plain app-private preferences are enough. */
class AppSettings(context: Context) {
    private val preferences = context.getSharedPreferences("appearance", Context.MODE_PRIVATE)
    private val state = MutableStateFlow(
        ThemeSettings(
            mode = runCatching { ThemeMode.valueOf(preferences.getString(KEY_MODE, null).orEmpty()) }
                .getOrDefault(ThemeMode.DARK),
            darkThemeId = preferences.getString(KEY_DARK, null) ?: Themes.DEFAULT_DARK,
            lightThemeId = preferences.getString(KEY_LIGHT, null) ?: Themes.DEFAULT_LIGHT,
        ),
    )
    val theme: StateFlow<ThemeSettings> = state.asStateFlow()

    fun setMode(mode: ThemeMode) = change { it.copy(mode = mode) }

    /** Picking a theme also switches to the matching mode, unless the app follows the system. */
    fun selectTheme(palette: ThemePalette) = change {
        val picked = if (palette.isLight) it.copy(lightThemeId = palette.id) else it.copy(darkThemeId = palette.id)
        if (it.mode == ThemeMode.SYSTEM) picked
        else picked.copy(mode = if (palette.isLight) ThemeMode.LIGHT else ThemeMode.DARK)
    }

    private fun change(transform: (ThemeSettings) -> ThemeSettings) {
        state.update(transform)
        val value = state.value
        preferences.edit()
            .putString(KEY_MODE, value.mode.name)
            .putString(KEY_DARK, value.darkThemeId)
            .putString(KEY_LIGHT, value.lightThemeId)
            .apply()
    }

    private companion object {
        const val KEY_MODE = "mode"
        const val KEY_DARK = "dark_theme"
        const val KEY_LIGHT = "light_theme"
    }
}
