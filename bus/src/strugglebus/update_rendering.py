"""Escaped views for the prepare-only operator update workflow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from html import escape
from typing import TYPE_CHECKING

from strugglebus.operator_lifecycle_rendering import disclosure, facts, hidden, panel
from strugglebus.maintenance_types import MaintenanceStatus
from strugglebus.update_types import UpdateCandidate, UpdateObservation, UpdateStatus

if TYPE_CHECKING:
    from strugglebus.operator_updates import UpdateReview

ROOT = "/operator/updates"
BOUNDARY = (
    "Prepared means verified release files only. Nothing is installed or executed; "
    "the running application, database and freeze state are unchanged. "
    "A later deployment requires separate approval and live safety checks."
)


def _time(value: int | None) -> str:
    if value is None:
        return "Not recorded"
    if value > 253402300799:
        return f"{value} UTC epoch seconds"
    return (datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=value)).isoformat()


def navigation() -> str:
    return f'<p class="section-gap"><a href="{ROOT}">Update overview</a> &middot; <a href="/system">Administration</a></p>'


def refresh(path: str) -> str:
    return f'<p><a class="button secondary" href="{escape(path, quote=True)}">Refresh status</a></p>'


def disabled() -> str:
    return panel(
        "Update preparation is disabled",
        "<p>This bus is not set up to fetch releases from this page. Whoever runs the "
        "server turns that on as a separate, approved setup step.</p>",
        description=BOUNDARY,
    )


def maintenance_disabled() -> str:
    return panel(
        "Self-installation is disabled",
        "<p>This bus is not set up to install releases itself. Finding and fetching a "
        "release never installs, activates or schedules it.</p>",
    )


def maintenance_failure(code: str) -> str:
    message = {
        "unavailable": "The root-owned maintenance supervisor is unavailable.",
        "unknown_outcome": (
            "The maintenance supervisor received the request, but its result could not "
            "be confirmed. Inspect current status before retrying."
        ),
        "busy": "A maintenance operation is already active.",
        "conflict": "The requested maintenance operation conflicts with current state.",
        "paused": "Automatic maintenance is paused. Manual updates remain available.",
        "outside_window": "The automatic request is outside its configured maintenance window.",
        "no_candidate": "No eligible newer release is available.",
        "updater_unavailable": "The release preparation worker is unavailable.",
        "preparation_failed": "The release could not be independently prepared and verified.",
        "installation_failed": (
            "Installation failed. The supervisor stopped and preserved recovery evidence."
        ),
        "state_corrupt": "Maintenance state is corrupt or unsupported. Protected recovery is required.",
        "forbidden": "The maintenance supervisor refused the caller identity.",
    }.get(code, f"The maintenance supervisor refused this operation ({code}).")
    return panel("Maintenance unavailable", f'<p role="alert">{escape(message)}</p>')


def maintenance_status(value: MaintenanceStatus) -> str:
    policy = value.policy
    body = panel(
        "Automatic maintenance",
        facts({
            "Automatic updates": "Enabled" if policy.enabled else "Paused",
            "Daily window": f"{policy.hour:02d}:{policy.minute:02d} {policy.timezone}",
            "Window length": f"{policy.window_minutes} minutes",
            "Advance notice": f"{policy.notice_seconds // 60} minutes in #announce",
            "Next window": _time(value.next_window),
            "Current application version": value.current_version,
        }),
        description=(
            "At most one automatic attempt is made in each daily window. A failed attempt "
            "waits for the next window and preserves evidence for protected recovery."
        ),
    )
    if value.attempt is not None:
        attempt = value.attempt
        body += panel(
            "Last maintenance attempt",
            facts({
                "Operation ID": attempt.operation_id,
                "Mode": attempt.mode,
                "Phase": attempt.phase,
                "Deciding identity": attempt.actor_id,
                "Candidate version": attempt.candidate_version or "None",
                "Started": _time(attempt.started_at),
                "Finished": _time(attempt.finished_at),
                "Failure code": attempt.error or "None",
            }),
        )
    return body


def maintenance_controls(value: MaintenanceStatus, csrf: str) -> str:
    policy = value.policy
    toggle = "false" if policy.enabled else "true"
    toggle_label = "Pause automatic updates" if policy.enabled else "Resume automatic updates"
    return panel(
        "Maintenance controls",
        (
            "<p>Every change requires your current operator password. Pausing automatic "
            "updates does not disable manual updates.</p>"
            f'<form method="post" action="{ROOT}/maintenance/toggle" class="form-stack">'
            f'{hidden("csrf", csrf)}{hidden("enabled", toggle)}'
            '<div class="field"><label for="maintenance-toggle-password">Operator password</label>'
            '<input id="maintenance-toggle-password" name="password" type="password" '
            'autocomplete="current-password" maxlength="1024" required></div>'
            f'<div class="form-actions"><button type="submit">{toggle_label}</button></div></form>'
            f'<form method="post" action="{ROOT}/maintenance/schedule" class="form-stack">'
            f'{hidden("csrf", csrf)}'
            '<div class="field"><label for="maintenance-hour">Brisbane hour (0-23)</label>'
            f'<input id="maintenance-hour" name="hour" type="number" min="0" max="23" '
            f'value="{policy.hour}" required></div>'
            '<div class="field"><label for="maintenance-minute">Minute (0-59)</label>'
            f'<input id="maintenance-minute" name="minute" type="number" min="0" max="59" '
            f'value="{policy.minute}" required></div>'
            '<div class="field"><label for="maintenance-schedule-password">Operator password</label>'
            '<input id="maintenance-schedule-password" name="password" type="password" '
            'autocomplete="current-password" maxlength="1024" required></div>'
            '<div class="form-actions"><button type="submit">Change daily window</button></div></form>'
            f'<form method="post" action="{ROOT}/maintenance/install" class="form-stack">'
            f'{hidden("csrf", csrf)}'
            "<p>Manual update checks, verifies and installs the latest eligible release now. "
            "It posts the same five-minute #announce notice before stopping the service.</p>"
            '<div class="field"><label for="maintenance-install-password">Operator password</label>'
            '<input id="maintenance-install-password" name="password" type="password" '
            'autocomplete="current-password" maxlength="1024" required></div>'
            '<div class="form-actions"><button type="submit">Update now</button></div></form>'
        ),
    )


def failure(message: str, path: str | None) -> str:
    body = f'<p role="alert">{escape(message)}</p>'
    if path is not None:
        body += (
            "<p>A lost acknowledgement is not proof that no work occurred. "
            "Inspect this operation before starting another job.</p>" + refresh(path)
        )
    return panel("Update operation unavailable", body, description=BOUNDARY)


def worker_failure(code: str, path: str | None) -> str:
    message = {
        "unavailable": "The protected update worker is unavailable. The bus remains independent of it.",
        "unknown_outcome": "Worker acceptance could not be confirmed. Reconcile the exact operation receipt.",
        "invalid_response": "The worker reply could not be validated. No outcome can be inferred from this reply.",
        "busy": "The worker already has an active operation; there is no job queue.",
        "cooldown": "Release discovery is cooling down. Wait before explicitly checking again.",
        "rate_limited": "The update source or worker admission limit was reached.",
        "authentication_failed": "The worker could not authenticate its dedicated release-source credential.",
        "history_unavailable": "The receipt is absent or evicted, not proof that no work occurred.",
        "observation_expired": "The release observation expired. Check and review the release again.",
        "observation_mismatch": "The observed release changed. Review the current observation again.",
        "policy_mismatch": "The installed verifier policy does not match the reviewed candidate.",
        "verification_failed": "Release verification failed; the candidate is not prepared.",
        "publication_changed": "Publication identity changed during verification; the candidate was refused.",
        "storage_full": "The isolated cache cannot preserve its storage budget and free-space reserve.",
        "storage_unsafe": "Protected cache ownership, paths or filesystem checks were refused.",
        "state_corrupt": "Worker history is corrupt or unsupported. Protected local investigation is required.",
        "cleanup_pending": "Cache cleanup is unresolved. No new operation can bypass it.",
    }.get(code, f"The worker refused this operation ({code}). Inspect its status before retrying.")
    return failure(message, path)


def candidate(value: UpdateCandidate) -> str:
    identity = facts({
        "Version": value.version, "Repository": "NZCypher819/strugglebus",
        "Release ID": value.release_id, "Annotated tag": value.tag,
        "Tag object": value.tag_object_sha, "Source commit": value.commit,
        "Source tree": value.tree, "Verifier policy": value.policy_id,
        "Exact candidate digest": value.digest,
    })
    rows = "".join(
        "<tr>"
        f'<td>{escape(asset.name)}</td><td>{asset.asset_id}</td><td>{asset.size_bytes}</td>'
        f'<td><code>{escape(asset.sha256)}</code></td><td>{escape(asset.media_type)}</td></tr>'
        for asset in value.assets
    )
    assets = (
        '<div class="table-wrap"><table><caption>Exact published assets</caption><thead><tr>'
        '<th scope="col">File</th><th scope="col">ID</th><th scope="col">Bytes</th>'
        '<th scope="col">SHA-256</th><th scope="col">Media type</th>'
        "</tr></thead><tbody>" + rows + "</tbody></table></div>"
    )
    return identity + disclosure("Five verified-file identities", assets)


def _observation(value: UpdateObservation) -> str:
    discovery = value.discovery
    body = facts({
        "Checked": _time(value.checked_at), "Observation expires": _time(value.expires_at),
        "Application version checked": value.application_version,
        "Application release checked": value.application_release_id,
        "Release records inspected": discovery.inspected,
    })
    if not discovery.complete:
        body += "<p role=\"status\">Discovery is incomplete: only the bounded release window was inspected.</p>"
    if discovery.blocked_version is not None:
        body += facts({"Blocked version": discovery.blocked_version, "Reason": discovery.blocked_reason})
    elif discovery.candidate is not None:
        body += candidate(discovery.candidate)
    else:
        body += "<p>No eligible newer candidate was found in the inspected release window.</p>"
    return panel("Last release observation", body)


def status(value: UpdateStatus) -> str:
    body = panel("Worker", facts({
        "Current state": value.state, "Worker version": value.worker_version,
        "Verifier policy": value.policy_id,
    }), description=BOUNDARY)
    if not value.history_available:
        body += panel(
            "History unavailable",
            "<p>The requested receipt is absent or was evicted. This does not prove the operation did not run.</p>",
        )
    if value.operation is not None:
        operation = value.operation
        body += panel("Recorded operation", facts({
            "Operation ID": operation.operation_id, "Action": operation.action,
            "Phase": operation.phase, "Deciding identity": operation.actor_id,
            "Accepted": _time(operation.started_at), "Finished": _time(operation.finished_at),
            "Failure code": operation.error or "None",
        }))
    if value.observation is not None:
        body += _observation(value.observation)
    if value.prepared is not None:
        body += panel(
            "Currently prepared files",
            facts({
                "Verified": _time(value.prepared.verified_at),
                "Preparation operation": value.prepared.operation_id,
            }) + candidate(value.prepared.candidate),
            description="These cached files have not been installed. No runtime readiness is implied.",
        )
    return body


def controls(value: UpdateStatus, csrf: str) -> str:
    if value.state in {"checking", "preparing", "unavailable"}:
        return "<p>Refresh to reconcile the current operation before starting another job.</p>"
    body = (
        f'<form method="post" action="{ROOT}/check" class="form-stack">{hidden("csrf", csrf)}'
        '<div class="form-actions"><button type="submit">Check published releases</button></div></form>'
    )
    observation = value.observation
    if observation is not None and observation.discovery.candidate is not None:
        body += (
            f'<p><a class="button secondary" href="{ROOT}/review/{escape(observation.observation_id, quote=True)}">'
            "Review exact release</a></p>"
        )
    return body


def review(value: UpdateReview, csrf: str, seconds: int) -> str:
    body = candidate(value.candidate) + facts({
        "Application version": value.observation.application_version,
        "Application release": value.observation.application_release_id,
        "Worker version reviewed": value.worker_version,
        "Preparation operation": value.operation_id,
    })
    body += (
        "<p>This downloads exactly five release files into isolated cache storage. "
        "It may replace the previous inactive prepared cache; it never installs or activates a release. "
        "Hashes establish byte integrity, not independent publisher authenticity.</p>"
        f"<p>This session-bound review expires within {seconds} seconds. "
        "Your password authorizes only this exact cache job, not a later installation.</p>"
        f'<form method="post" action="{ROOT}/prepare" class="form-stack">{hidden("csrf", csrf)}'
        f'{hidden("review_id", value.review_id)}'
        '<div class="field"><label for="update-password">Operator password</label>'
        '<input id="update-password" name="password" type="password" autocomplete="current-password" '
        'maxlength="1024" required></div><div class="form-actions">'
        '<button type="submit">Prepare verified files</button></div></form>'
    )
    return panel("Prepare this exact release", body, description=BOUNDARY)
