package com.strugglebus.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.strugglebus.app.BuildConfig
import com.strugglebus.app.core.settings.AppSettings
import com.strugglebus.app.core.settings.ThemeMode
import com.strugglebus.app.ui.theme.RetroAmber
import com.strugglebus.app.ui.theme.RetroRed
import com.strugglebus.app.ui.theme.RetroTealMuted
import com.strugglebus.app.ui.theme.ThemePalette
import com.strugglebus.app.ui.theme.Themes

@Composable
fun SettingsScreen(
    settings: AppSettings,
    enrolled: Boolean,
    onRemoveEnrollment: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val theme by settings.theme.collectAsStateWithLifecycle()
    var confirmUnlink by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("APPEARANCE", style = MaterialTheme.typography.labelLarge, color = RetroAmber)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ThemeMode.entries.forEach { mode ->
                FilterChip(
                    selected = theme.mode == mode,
                    onClick = { settings.setMode(mode) },
                    label = {
                        Text(
                            when (mode) {
                                ThemeMode.DARK -> "DARK"
                                ThemeMode.LIGHT -> "LIGHT"
                                ThemeMode.SYSTEM -> "MATCH PHONE"
                            },
                            style = MaterialTheme.typography.labelMedium,
                        )
                    },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = MaterialTheme.colorScheme.primary,
                        selectedLabelColor = MaterialTheme.colorScheme.onPrimary,
                    ),
                )
            }
        }

        ThemeList("DARK THEME", Themes.all.filter { !it.isLight }, theme.darkThemeId, settings::selectTheme)
        ThemeList("LIGHT THEME", Themes.all.filter { it.isLight }, theme.lightThemeId, settings::selectTheme)

        Text(
            "Colours are the Omarchy palettes, the same set as the Windows app.",
            style = MaterialTheme.typography.bodySmall,
            color = RetroTealMuted,
        )

        if (enrolled) {
            Text(
                "THIS DEVICE",
                modifier = Modifier.padding(top = 8.dp),
                style = MaterialTheme.typography.labelLarge,
                color = RetroAmber,
            )
            Text(
                "Unlinking removes this phone's saved credential and operator access. " +
                    "It needs a fresh enrollment code to connect again.",
                style = MaterialTheme.typography.bodySmall,
                color = RetroTealMuted,
            )
            OutlinedButton(onClick = { confirmUnlink = true }) {
                Text("UNLINK DEVICE", color = RetroRed)
            }
        }

        Text(
            "APP ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
            modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
            style = MaterialTheme.typography.bodySmall,
            color = RetroTealMuted,
        )
    }

    if (confirmUnlink) {
        AlertDialog(
            onDismissRequest = { confirmUnlink = false },
            title = { Text("Unlink this device?") },
            text = { Text("The saved credential and operator access are removed from this phone.") },
            confirmButton = {
                Button(onClick = {
                    confirmUnlink = false
                    onRemoveEnrollment()
                }) { Text("UNLINK") }
            },
            dismissButton = { TextButton(onClick = { confirmUnlink = false }) { Text("CANCEL") } },
        )
    }
}

@Composable
private fun ThemeList(
    title: String,
    themes: List<ThemePalette>,
    selectedId: String,
    onSelect: (ThemePalette) -> Unit,
) {
    Text(title, modifier = Modifier.padding(top = 8.dp), style = MaterialTheme.typography.labelLarge, color = RetroAmber)
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        themes.forEach { palette ->
            val selected = palette.id == selectedId
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surface, MaterialTheme.shapes.medium)
                    .border(
                        width = if (selected) 2.dp else 1.dp,
                        color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
                        shape = MaterialTheme.shapes.medium,
                    )
                    .clickable(role = Role.RadioButton, onClick = { onSelect(palette) })
                    .padding(horizontal = 12.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(3.dp)) {
                    listOf(palette.background, palette.foreground, palette.accent, palette.ok, palette.warn, palette.bad)
                        .forEach { value ->
                            Box(
                                Modifier
                                    .size(16.dp)
                                    .background(Color(0xFF000000L or value.toLong()), MaterialTheme.shapes.extraSmall)
                                    .border(1.dp, MaterialTheme.colorScheme.outlineVariant, MaterialTheme.shapes.extraSmall),
                            )
                        }
                }
                Text(palette.name, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                if (selected) {
                    Text("SELECTED", style = MaterialTheme.typography.labelMedium, color = RetroAmber)
                }
            }
        }
    }
}
