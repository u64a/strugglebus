package com.strugglebus.app.ui

import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.strugglebus.app.BuildConfig
import com.strugglebus.app.core.model.OperatorAction
import com.strugglebus.app.ui.theme.RetroAmber
import com.strugglebus.app.ui.theme.RetroRed
import com.strugglebus.app.ui.theme.RetroTealMuted

@Composable
fun AdminScreen(
    viewModel: AdminViewModel,
    onDeviceRevoked: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var showGrantSetup by rememberSaveable { mutableStateOf(!state.grantConfigured) }

    LaunchedEffect(Unit) { viewModel.refresh() }
    LaunchedEffect(state.grantConfigured, state.loading, state.isFrozen) {
        if (!state.grantConfigured && !state.loading && !state.isFrozen) {
            showGrantSetup = true
        } else if (state.isFrozen) {
            showGrantSetup = false
        }
    }
    LaunchedEffect(state.deviceRevoked) {
        if (state.deviceRevoked) onDeviceRevoked()
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("OPERATOR CONTROLS", style = MaterialTheme.typography.headlineSmall, color = RetroAmber)
        Text(
            "Every write is bound to an exact target, reviewed, and authorized with this phone's biometric or screen lock.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (state.isFrozen) {
            AdminPanel(
                "FROZEN — monitoring and existing operator controls remain available. New operator grants cannot be created.",
                error = true,
            )
        }
        state.error?.let { AdminPanel(it, error = true) }
        state.detail?.let { AdminPanel(it, error = false) }

        Surface(
            color = MaterialTheme.colorScheme.surface,
            shape = MaterialTheme.shapes.medium,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("OPERATOR GRANT", style = MaterialTheme.typography.labelLarge, color = RetroAmber)
                Text(
                    if (state.grantConfigured) "Configured and protected by Android Keystore"
                    else "Not configured — write actions are unavailable",
                )
                if (!state.grantConfigured) {
                    Button(
                        enabled = !state.loading && !state.isFrozen,
                        onClick = { showGrantSetup = true },
                    ) { Text("SET UP OPERATOR ACCESS") }
                }
            }
        }

        EnrollSection(viewModel, state)

        Text("BUS CONTAINMENT", style = MaterialTheme.typography.labelLarge, color = RetroAmber)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                enabled = state.grantConfigured && !state.loading && !state.isFrozen,
                onClick = {
                    viewModel.requestAction(OperatorAction.ACTIVATE_FREEZE, GLOBAL_TARGET_ID)
                },
            ) { Text("ACTIVATE FREEZE") }
            OutlinedButton(
                enabled = state.grantConfigured && !state.loading && state.isFrozen,
                onClick = {
                    viewModel.requestAction(OperatorAction.CLEAR_FREEZE, GLOBAL_TARGET_ID)
                },
            ) { Text("CLEAR FREEZE") }
        }

        Text("AGENT CONTAINMENT", style = MaterialTheme.typography.labelLarge, color = RetroAmber)
        if (state.agents.isEmpty()) {
            Text("No agents available", color = RetroTealMuted)
        } else {
            state.agents.forEach { agent ->
                Surface(
                    color = MaterialTheme.colorScheme.surface,
                    shape = MaterialTheme.shapes.medium,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(agent.name)
                            Text(agent.host, style = MaterialTheme.typography.bodySmall, color = RetroTealMuted)
                        }
                        OutlinedButton(
                            enabled = state.grantConfigured && !state.loading,
                            onClick = {
                                viewModel.requestAction(OperatorAction.BLOCK_AGENT, agent.id)
                            },
                        ) { Text("BLOCK") }
                    }
                }
            }
        }

        Text("DEVICE CONTAINMENT", style = MaterialTheme.typography.labelLarge, color = RetroAmber)
        OutlinedButton(
            enabled = state.grantConfigured && !state.loading && state.deviceId != null,
            onClick = {
                state.deviceId?.let {
                    viewModel.requestAction(OperatorAction.REVOKE_DEVICE, it)
                }
            },
        ) {
            Text("REVOKE THIS DEVICE", color = RetroRed)
        }
        Text(
            "Revocation immediately removes this phone's monitor and operator access and requires fresh enrollment.",
            style = MaterialTheme.typography.bodySmall,
            color = RetroTealMuted,
        )

        if (state.loading) CircularProgressIndicator()

        Text(
            "APP ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})  •  MOBILE API $MOBILE_API_VERSION",
            modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
            style = MaterialTheme.typography.bodySmall,
            color = RetroTealMuted,
        )
    }

    if (showGrantSetup && !state.grantConfigured) {
        GrantSetupDialog(
            loading = state.loading,
            onDismiss = { if (!state.loading) showGrantSetup = false },
            onSubmit = { password ->
                showGrantSetup = false
                viewModel.establishGrant(password)
            },
        )
    }

    state.confirmation?.let { confirmation ->
        ActionConfirmationDialog(
            viewModel = viewModel,
            effect = confirmation.effect,
            loading = state.loading,
            onDismiss = viewModel::cancelConfirmation,
        )
    }
}

@Composable
private fun GrantSetupDialog(
    loading: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (String) -> Unit,
) {
    var password by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Set up operator access") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Enter the StruggleBus operator password once. It is exchanged for a revocable device grant and is never stored.")
                OutlinedTextField(
                    value = password,
                    onValueChange = { if (it.length <= 1024) password = it },
                    label = { Text("Operator password") },
                    visualTransformation = PasswordVisualTransformation(),
                    enabled = !loading,
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            Button(
                enabled = !loading && password.length >= 15,
                onClick = {
                    val submitted = password
                    password = ""
                    onSubmit(submitted)
                },
            ) { Text("ESTABLISH GRANT") }
        },
        dismissButton = { TextButton(enabled = !loading, onClick = onDismiss) { Text("CANCEL") } },
    )
}

@Composable
private fun ActionConfirmationDialog(
    viewModel: AdminViewModel,
    effect: String,
    loading: Boolean,
    onDismiss: () -> Unit,
) {
    var reason by remember(effect) { mutableStateOf("") }
    val context = LocalContext.current
    val activity = context as? FragmentActivity
    val executor = remember(context) { ContextCompat.getMainExecutor(context) }
    val prompt = remember(activity, executor, reason) {
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
                            viewModel.performConfirmedAction(cipher, reason)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        viewModel.authenticationFailed(errString.toString())
                    }
                },
            )
        }
    }

    AlertDialog(
        onDismissRequest = { if (!loading) onDismiss() },
        title = { Text("Confirm exact effect") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(effect)
                OutlinedTextField(
                    value = reason,
                    onValueChange = {
                        if (it.length <= 256 && it.toByteArray(Charsets.UTF_8).size <= 1_024) {
                            reason = it
                        }
                    },
                    label = { Text("Audit reason") },
                    supportingText = {
                        Text("Truthful, non-secret text only. Do not include credentials, messages, addresses, or host data.")
                    },
                    enabled = !loading,
                    minLines = 2,
                )
                Text(
                    "After continuing, Android will require your biometric or device PIN before anything is submitted.",
                    style = MaterialTheme.typography.bodySmall,
                    color = RetroTealMuted,
                )
            }
        },
        confirmButton = {
            Button(
                enabled = !loading && reason.isNotBlank() && prompt != null,
                onClick = {
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
                            .setSubtitle(effect)
                            .setAllowedAuthenticators(authenticators)
                            .build()
                        prompt?.authenticate(
                            promptInfo,
                            BiometricPrompt.CryptoObject(viewModel.createAuthenticationCipher()),
                        )
                    }.onFailure {
                        viewModel.authenticationFailed(
                            it.message ?: "Unable to start device authentication.",
                        )
                    }
                },
            ) { Text("AUTHORIZE") }
        },
        dismissButton = {
            TextButton(enabled = !loading, onClick = onDismiss) { Text("CANCEL") }
        },
    )
}

@Composable
private fun AdminPanel(message: String, error: Boolean) {
    val color = if (error) RetroRed else RetroAmber
    Surface(
        color = MaterialTheme.colorScheme.surface,
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, color, MaterialTheme.shapes.medium),
        shape = MaterialTheme.shapes.medium,
    ) {
        Text(message, modifier = Modifier.padding(12.dp), color = color)
    }
}

private const val GLOBAL_TARGET_ID = "global"
private const val MOBILE_API_VERSION = 1
