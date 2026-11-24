package com.strugglebus.app.core.model

enum class OperatorAction(val wireName: String) {
    REVOKE_DEVICE("revoke-device"),
    BLOCK_AGENT("block-agent"),
    ACTIVATE_FREEZE("activate-freeze"),
    CLEAR_FREEZE("clear-freeze"),
}

data class WriteGrantResult(
    val deviceId: String,
    val grantSecret: String,
)

data class ActionConfirmation(
    val id: String,
    val action: OperatorAction,
    val targetKind: String,
    val targetId: String,
    val targetLabel: String,
    val expiresAt: String,
    val effect: String,
)

data class OperatorActionResult(
    val action: OperatorAction,
    val targetId: String,
    val targetLabel: String,
    val applied: Boolean,
    val detail: String,
)

/** The only kinds the server accepts from a human post to #humans. */
enum class HumanMessageKind(val wireName: String) {
    CHAT("chat"),
    QUESTION("question"),
    ANSWER("answer"),
}

enum class EnrollmentKind(val label: String) {
    AGENT("AGENT"),
    SERVICE_PRINCIPAL("SERVICE PRINCIPAL"),
    DEVICE("DEVICE"),
}

/** What the operator asked to enroll. [extra] is the description (agent) or worker-name prefix (service principal). */
data class EnrollmentRequest(
    val kind: EnrollmentKind,
    val name: String,
    val extra: String,
    val reason: String,
)

/** The one-time result of an enrollment. [secret] is shown once and never stored by the app. */
data class EnrollmentOutcome(
    val title: String,
    val detail: String,
    val secret: String?,
)
