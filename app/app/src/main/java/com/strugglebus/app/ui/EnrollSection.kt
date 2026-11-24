package com.strugglebus.app.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.strugglebus.app.core.model.EnrollmentKind
import com.strugglebus.app.core.model.EnrollmentOutcome
import com.strugglebus.app.core.model.EnrollmentRequest
import com.strugglebus.app.ui.theme.RetroAmber
import com.strugglebus.app.ui.theme.RetroCream
import com.strugglebus.app.ui.theme.RetroTealMuted
import javax.crypto.Cipher

/** Enroll an agent, a service principal or another device, authorized by this phone's screen lock. */
@Composable
fun EnrollSection(viewModel: AdminViewModel, state: AdminUiState) {
    var kind by rememberSaveable { mutableStateOf(EnrollmentKind.AGENT) }
    var name by rememberSaveable { mutableStateOf("") }
    var extra by rememberSaveable { mutableStateOf("") }
    var reason by rememberSaveable { mutableStateOf("") }
    val request = EnrollmentRequest(kind, name, extra, reason)
    val problem = viewModel.enrollmentProblem(request)
    val authorize = rememberGrantPrompt(viewModel) { cipher ->
        viewModel.createEnrollment(request, cipher)
    }
    // The form is kept until the bus has answered, so a failed attempt does not lose what was typed.
    LaunchedEffect(state.enrollment) {
        if (state.enrollment != null) {
            name = ""
            extra = ""
            reason = ""
        }
    }

    Text("ENROLL", style = MaterialTheme.typography.labelLarge, color = RetroAmber)
    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                modifier = Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                EnrollmentKind.entries.forEach { option ->
                    FilterChip(
                        selected = kind == option,
                        onClick = { kind = option },
                        label = { Text(option.label, style = MaterialTheme.typography.labelMedium) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = MaterialTheme.colorScheme.primary,
                            selectedLabelColor = MaterialTheme.colorScheme.onPrimary,
                        ),
                    )
                }
            }
            Text(
                when (kind) {
                    EnrollmentKind.AGENT ->
                        "Creates a single-use onboarding package to hand to a new agent."
                    EnrollmentKind.SERVICE_PRINCIPAL ->
                        "Creates a credential that can start short-lived worker agents."
                    EnrollmentKind.DEVICE ->
                        "Creates a single-use code for another phone or PC."
                },
                style = MaterialTheme.typography.bodySmall,
                color = RetroTealMuted,
            )
            OutlinedTextField(
                value = name,
                onValueChange = { if (it.length <= 64) name = it },
                label = {
                    Text(
                        when (kind) {
                            EnrollmentKind.AGENT -> "Agent name, for example build-helper"
                            EnrollmentKind.SERVICE_PRINCIPAL -> "Service principal name"
                            EnrollmentKind.DEVICE -> "Device label, for example Kitchen tablet"
                        },
                    )
                },
                singleLine = true,
                enabled = !state.loading,
                modifier = Modifier.fillMaxWidth(),
            )
            if (kind != EnrollmentKind.DEVICE) {
                OutlinedTextField(
                    value = extra,
                    onValueChange = { if (it.length <= 128) extra = it },
                    label = {
                        Text(
                            if (kind == EnrollmentKind.AGENT) "What it does (optional)"
                            else "Worker names start with, for example build-worker",
                        )
                    },
                    singleLine = true,
                    enabled = !state.loading,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            OutlinedTextField(
                value = reason,
                onValueChange = { if (it.length <= 256) reason = it },
                label = { Text("Audit reason") },
                supportingText = { Text("Non-secret text. It is recorded with the enrollment.") },
                enabled = !state.loading,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                enabled = state.grantConfigured && !state.loading && !state.isFrozen && problem == null,
                onClick = { authorize("Enroll ${kind.label.lowercase()} ${name.trim()}") },
            ) { Text("AUTHORIZE AND ENROLL") }
            val hint = when {
                !state.grantConfigured -> "Set up operator access first."
                state.isFrozen -> "Enrollment is blocked while the bus is frozen."
                name.isNotBlank() || reason.isNotBlank() -> problem
                else -> null
            }
            hint?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = RetroTealMuted) }
        }
    }

    state.enrollment?.let { outcome -> EnrollmentResultPanel(outcome, onClear = viewModel::clearEnrollment) }
}

@Composable
private fun EnrollmentResultPanel(outcome: EnrollmentOutcome, onClear: () -> Unit) {
    val context = LocalContext.current
    var copied by remember(outcome) { mutableStateOf(false) }
    Surface(
        color = MaterialTheme.colorScheme.surface,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, MaterialTheme.colorScheme.primary, MaterialTheme.shapes.medium),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(outcome.title, style = MaterialTheme.typography.labelLarge, color = RetroAmber)
            Text(outcome.detail, style = MaterialTheme.typography.bodySmall, color = RetroTealMuted)
            outcome.secret?.let { secret ->
                Text(
                    "SHOWN ONCE. It is gone when you clear it or leave this page.",
                    style = MaterialTheme.typography.labelMedium,
                    color = RetroAmber,
                )
                SelectionContainer {
                    Text(
                        secret,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 220.dp)
                            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, MaterialTheme.shapes.small)
                            .verticalScroll(rememberScrollState())
                            .padding(10.dp),
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = RetroCream,
                    )
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                outcome.secret?.let { secret ->
                    Button(onClick = {
                        copySensitive(context, secret)
                        copied = true
                    }) { Text(if (copied) "COPIED" else "COPY") }
                }
                OutlinedButton(onClick = onClear) { Text("CLEAR") }
            }
        }
    }
}

private fun copySensitive(context: Context, text: String) {
    val clip = ClipData.newPlainText("StruggleBus enrollment", text)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        // Keeps the secret out of the clipboard preview and keyboard suggestions.
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(clip)
}

/**
 * Returns a function that asks for the phone's biometric or screen lock and, on success, hands
 * the unlocked grant cipher to [onAuthorized]. The argument is the text shown under the prompt.
 */
@Composable
fun rememberGrantPrompt(viewModel: AdminViewModel, onAuthorized: (Cipher) -> Unit): (String) -> Unit {
    val context = LocalContext.current
    val activity = context as? FragmentActivity
    val executor = remember(context) { ContextCompat.getMainExecutor(context) }
    val currentOnAuthorized by rememberUpdatedState(onAuthorized)
    val prompt = remember(activity, executor) {
        activity?.let {
            BiometricPrompt(
                it,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val cipher = result.cryptoObject?.cipher
                        if (cipher == null) {
                            viewModel.authenticationFailed("Android did not return the authenticated key.")
                        } else {
                            currentOnAuthorized(cipher)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        viewModel.authenticationFailed(errString.toString())
                    }
                },
            )
        }
    }
    return { subtitle ->
        runCatching {
            val authenticators = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
            } else {
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            }
            check(
                BiometricManager.from(context).canAuthenticate(authenticators) ==
                    BiometricManager.BIOMETRIC_SUCCESS,
            ) { "Set up a supported biometric or device screen lock first." }
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authorize StruggleBus action")
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(authenticators)
                .build()
            checkNotNull(prompt) { "Device authentication is unavailable here." }
                .authenticate(promptInfo, BiometricPrompt.CryptoObject(viewModel.createAuthenticationCipher()))
        }.onFailure {
            viewModel.authenticationFailed(it.message ?: "Unable to start device authentication.")
        }
    }
}
