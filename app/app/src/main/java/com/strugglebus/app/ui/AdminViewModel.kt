package com.strugglebus.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.strugglebus.app.activity.AdminRepository
import com.strugglebus.app.core.model.ActionConfirmation
import com.strugglebus.app.core.model.BusAgent
import com.strugglebus.app.core.model.BusStatus
import com.strugglebus.app.core.model.EnrollmentKind
import com.strugglebus.app.core.model.EnrollmentOutcome
import com.strugglebus.app.core.model.EnrollmentRequest
import com.strugglebus.app.core.model.OperatorAction
import com.strugglebus.app.core.network.ApiException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.crypto.Cipher

data class AdminUiState(
    val grantConfigured: Boolean = false,
    val deviceId: String? = null,
    val loading: Boolean = false,
    val isFrozen: Boolean = false,
    val agents: List<BusAgent> = emptyList(),
    val confirmation: ActionConfirmation? = null,
    val detail: String? = null,
    val error: String? = null,
    val deviceRevoked: Boolean = false,
    /** The result of the last enrollment. Its secret is shown once and held only in memory. */
    val enrollment: EnrollmentOutcome? = null,
)

class AdminViewModel(
    private val repository: AdminRepository,
) : ViewModel() {
    private val _uiState = MutableStateFlow(
        AdminUiState(
            grantConfigured = repository.hasGrant(),
            deviceId = repository.currentDeviceId(),
        ),
    )
    val uiState: StateFlow<AdminUiState> = _uiState.asStateFlow()

    fun refresh() {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    loading = true,
                    error = null,
                    grantConfigured = repository.hasGrant(),
                    deviceId = repository.currentDeviceId(),
                    deviceRevoked = false,
                )
            }
            runCatching { repository.status() to repository.agents() }
                .onSuccess { (status, agents) ->
                    _uiState.update {
                        it.copy(
                            loading = false,
                            isFrozen = status == BusStatus.FROZEN,
                            agents = agents,
                        )
                    }
                }
                .onFailure { failure ->
                    failure.rethrowCancellation()
                    _uiState.update { it.copy(loading = false, error = failure.safeMessage()) }
                }
        }
    }

    fun establishGrant(operatorPassword: String) {
        if (operatorPassword.isBlank()) return
        viewModelScope.launch {
            _uiState.update { it.copy(loading = true, error = null, detail = null) }
            runCatching { repository.establishGrant(operatorPassword) }
                .onSuccess {
                    _uiState.update {
                        it.copy(
                            loading = false,
                            grantConfigured = true,
                            deviceId = repository.currentDeviceId(),
                            detail = "Operator access is protected by this device's biometric or screen lock.",
                        )
                    }
                }
                .onFailure { failure ->
                    failure.rethrowCancellation()
                    _uiState.update { it.copy(loading = false, error = failure.safeMessage()) }
                }
        }
    }

    fun requestAction(action: OperatorAction, targetId: String) {
        viewModelScope.launch {
            _uiState.update { it.copy(loading = true, error = null, detail = null) }
            runCatching { repository.requestConfirmation(action, targetId) }
                .onSuccess { confirmation ->
                    _uiState.update { it.copy(loading = false, confirmation = confirmation) }
                }
                .onFailure { failure ->
                    failure.rethrowCancellation()
                    _uiState.update { it.copy(loading = false, error = failure.safeMessage()) }
                }
        }
    }

    fun createAuthenticationCipher(): Cipher = repository.createGrantDecryptionCipher()

    fun performConfirmedAction(authenticatedCipher: Cipher, reason: String) {
        val confirmation = _uiState.value.confirmation ?: return
        if (reason.isBlank()) {
            _uiState.update { it.copy(error = "Enter an audit reason before authorizing the action.") }
            return
        }
        viewModelScope.launch {
            _uiState.update { it.copy(loading = true, error = null) }
            runCatching {
                repository.performAction(confirmation, authenticatedCipher, reason.trim())
            }.onSuccess { result ->
                val revoked = result.applied && result.action == OperatorAction.REVOKE_DEVICE
                if (revoked) repository.clearGrant()
                _uiState.update {
                    it.copy(
                        loading = false,
                        grantConfigured = !revoked,
                        confirmation = null,
                        detail = result.detail,
                        deviceRevoked = revoked,
                        isFrozen = when (result.action) {
                            OperatorAction.ACTIVATE_FREEZE -> if (result.applied) true else it.isFrozen
                            OperatorAction.CLEAR_FREEZE -> if (result.applied) false else it.isFrozen
                            else -> it.isFrozen
                        },
                    )
                }
                refresh()
            }.onFailure { failure ->
                failure.rethrowCancellation()
                if (failure is ApiException && failure.statusCode == 401) {
                    repository.clearGrant()
                    _uiState.update { it.copy(grantConfigured = false) }
                }
                _uiState.update { it.copy(loading = false, error = failure.safeMessage()) }
            }
        }
    }

    /** Describes what is missing from an enrollment form, or null when it can be submitted. */
    fun enrollmentProblem(request: EnrollmentRequest): String? = when {
        request.name.isBlank() -> "Enter a name."
        request.kind != EnrollmentKind.DEVICE && !FeedLogic.isMentionable(request.name.trim()) ->
            "Use lowercase words joined by hyphens, for example build-helper."
        request.kind == EnrollmentKind.SERVICE_PRINCIPAL && !FeedLogic.isMentionable(request.extra.trim() + "-x") ->
            "Enter the name its workers start with, for example build-worker."
        request.reason.isBlank() -> "Enter an audit reason."
        else -> null
    }

    fun createEnrollment(request: EnrollmentRequest, authenticatedCipher: Cipher) {
        enrollmentProblem(request)?.let { problem ->
            _uiState.update { it.copy(error = problem) }
            return
        }
        val cleaned = request.copy(
            name = request.name.trim(),
            extra = request.extra.trim(),
            reason = request.reason.trim(),
        )
        viewModelScope.launch {
            _uiState.update { it.copy(loading = true, error = null, detail = null, enrollment = null) }
            runCatching { repository.createEnrollment(cleaned, authenticatedCipher) }
                .onSuccess { outcome ->
                    _uiState.update { it.copy(loading = false, enrollment = outcome) }
                }
                .onFailure { failure ->
                    failure.rethrowCancellation()
                    val status = (failure as? ApiException)?.statusCode
                    if (status == 401) {
                        repository.clearGrant()
                        _uiState.update { it.copy(grantConfigured = false) }
                    }
                    val message = if (failure is UnsupportedOperationException || status in setOf(404, 405)) {
                        "This bus cannot enroll from a device yet. It needs StruggleBus 0.2.62 or later."
                    } else {
                        failure.safeMessage()
                    }
                    _uiState.update { it.copy(loading = false, error = message) }
                }
        }
    }

    /** Forgets the displayed enrollment secret. */
    fun clearEnrollment() {
        _uiState.update { it.copy(enrollment = null) }
    }

    fun cancelConfirmation() {
        _uiState.update { it.copy(confirmation = null, error = null) }
    }

    fun authenticationFailed(message: String) {
        _uiState.update { it.copy(error = message) }
    }

    fun updateFrozen(isFrozen: Boolean) {
        _uiState.update { it.copy(isFrozen = isFrozen) }
    }

    fun clearMessages() {
        _uiState.update { it.copy(detail = null, error = null) }
    }

    private fun Throwable.rethrowCancellation() {
        if (this is CancellationException) throw this
    }

    private fun Throwable.safeMessage(): String =
        message?.takeIf(String::isNotBlank) ?: "Unable to complete the operator request."
}
