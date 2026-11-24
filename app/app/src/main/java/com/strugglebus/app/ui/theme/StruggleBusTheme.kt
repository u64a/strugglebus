package com.strugglebus.app.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** The current palette's colours as Compose colours. */
data class AppColors(
    val isLight: Boolean,
    val bg: Color,
    val fg: Color,
    val accent: Color,
    val ok: Color,
    val warn: Color,
    val bad: Color,
    val surface1: Color,
    val surface2: Color,
    val line: Color,
    val muted: Color,
    val soft: Color,
    val accentSoft: Color,
    val accentText: Color,
    val okText: Color,
    val badText: Color,
    val onAccent: Color,
    val onBad: Color,
)

private fun rgb(value: Int): Color = Color(0xFF000000L or (value.toLong() and 0xFFFFFFL))

fun ThemePalette.toAppColors(): AppColors {
    val derived = Themes.derive(this)
    return AppColors(
        isLight = isLight,
        bg = rgb(derived.bg),
        fg = rgb(derived.fg),
        accent = rgb(derived.accent),
        ok = rgb(derived.ok),
        warn = rgb(derived.warn),
        bad = rgb(derived.bad),
        surface1 = rgb(derived.surface1),
        surface2 = rgb(derived.surface2),
        line = rgb(derived.line),
        muted = rgb(derived.muted),
        soft = rgb(derived.soft),
        accentSoft = rgb(derived.accentSoft),
        accentText = rgb(derived.accentText),
        okText = rgb(derived.okText),
        badText = rgb(derived.badText),
        onAccent = rgb(derived.onAccent),
        onBad = rgb(derived.onBad),
    )
}

val LocalAppColors = staticCompositionLocalOf { Themes.find(Themes.DEFAULT_DARK, light = false).toAppColors() }

// The screens were written against these names. They now follow the selected palette.
val RetroCream: Color @Composable @ReadOnlyComposable get() = LocalAppColors.current.fg
val RetroAmber: Color @Composable @ReadOnlyComposable get() = LocalAppColors.current.accentText
val RetroTeal: Color @Composable @ReadOnlyComposable get() = LocalAppColors.current.soft
val RetroTealMuted: Color @Composable @ReadOnlyComposable get() = LocalAppColors.current.muted
val RetroGreen: Color @Composable @ReadOnlyComposable get() = LocalAppColors.current.okText
val RetroRed: Color @Composable @ReadOnlyComposable get() = LocalAppColors.current.badText

private fun AppColors.toColorScheme(): ColorScheme {
    val base = if (isLight) lightColorScheme() else darkColorScheme()
    return base.copy(
        primary = accent,
        onPrimary = onAccent,
        primaryContainer = accentSoft,
        onPrimaryContainer = fg,
        secondary = soft,
        onSecondary = bg,
        secondaryContainer = surface2,
        onSecondaryContainer = fg,
        tertiary = warn,
        onTertiary = bg,
        background = bg,
        onBackground = fg,
        surface = surface1,
        onSurface = fg,
        surfaceVariant = surface2,
        onSurfaceVariant = soft,
        surfaceTint = accent,
        outline = muted,
        outlineVariant = line,
        error = badText,
        onError = bg,
        errorContainer = bad,
        onErrorContainer = onBad,
        scrim = bg,
    )
}

private val RetroTypography = Typography(
    headlineSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        fontSize = 22.sp,
        lineHeight = 28.sp,
        letterSpacing = 0.4.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        fontSize = 20.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.3.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        lineHeight = 20.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.SemiBold,
        fontSize = 13.sp,
        lineHeight = 18.sp,
        letterSpacing = 0.3.sp,
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.2.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontSize = 16.sp,
        lineHeight = 23.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        lineHeight = 15.sp,
        letterSpacing = 0.1.sp,
    ),
)

private val RetroShapes = Shapes(
    extraSmall = RoundedCornerShape(2.dp),
    small = RoundedCornerShape(2.dp),
    medium = RoundedCornerShape(3.dp),
    large = RoundedCornerShape(4.dp),
    extraLarge = RoundedCornerShape(4.dp),
)

@Composable
fun StruggleBusTheme(
    palette: ThemePalette = Themes.find(Themes.DEFAULT_DARK, light = false),
    content: @Composable () -> Unit,
) {
    val colors = remember(palette) { palette.toAppColors() }
    CompositionLocalProvider(LocalAppColors provides colors) {
        MaterialTheme(
            colorScheme = remember(colors) { colors.toColorScheme() },
            typography = RetroTypography,
            shapes = RetroShapes,
            content = content,
        )
    }
}
