package com.strugglebus.app

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.LifecycleStartEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.strugglebus.app.ui.AdminViewModel
import com.strugglebus.app.ui.BusMonitorScreen
import com.strugglebus.app.ui.BusMonitorViewModel
import com.strugglebus.app.ui.HumansViewModel
import com.strugglebus.app.ui.theme.StruggleBusTheme

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            val repository = (application as StruggleBusApplication).repository
            val monitorViewModel = viewModel { BusMonitorViewModel(repository) }
            val adminViewModel = viewModel {
                AdminViewModel((application as StruggleBusApplication).adminRepository)
            }
            val humansViewModel = viewModel {
                HumansViewModel((application as StruggleBusApplication).humansRepository)
            }
            LifecycleStartEffect(monitorViewModel) {
                monitorViewModel.onForeground()
                onStopOrDispose { monitorViewModel.onBackground() }
            }
            val settings = (application as StruggleBusApplication).settings
            val theme by settings.theme.collectAsStateWithLifecycle()
            val palette = theme.resolve(systemPrefersLight = !isSystemInDarkTheme())
            val view = LocalView.current
            SideEffect {
                // Status and navigation bar icons must contrast with the palette's background.
                val background = (0xFF000000L or palette.background.toLong()).toInt()
                @Suppress("DEPRECATION")
                run {
                    window.statusBarColor = background
                    window.navigationBarColor = background
                }
                WindowCompat.getInsetsController(window, view).apply {
                    isAppearanceLightStatusBars = palette.isLight
                    isAppearanceLightNavigationBars = palette.isLight
                }
            }
            StruggleBusTheme(palette) {
                Surface(color = MaterialTheme.colorScheme.background) {
                    BusMonitorScreen(monitorViewModel, adminViewModel, humansViewModel, settings)
                }
            }
        }
    }

}
