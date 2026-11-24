"""Server-computed orientation for connecting and reconnecting agents.

Derive ordered bootstrap requirements and advisory coordination steps from
observed state, without treating cursor timestamps as session history.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from strugglebus.models import AgentOrientation, EffectiveRoe


@dataclass(frozen=True, slots=True)
class RequiredAction:
    action: str
    reason: str


def _plural(count: int, capped: bool, noun: str) -> str:
    amount = f"at least {count}" if capped else str(count)
    suffix = "" if count == 1 and not capped else "s"
    return f"{amount} {noun}{suffix}"


def _roe_action(roe: EffectiveRoe) -> RequiredAction | None:
    """The acknowledgement step a missing or stale receipt calls for."""

    if roe.acknowledgement_status == "missing":
        return RequiredAction(
            action="acknowledge_roe",
            reason=(
                "This credential has not recorded receipt of the rules of "
                "engagement. Call get_effective_roe, then acknowledge_roe "
                "with the exact returned revision IDs and hashes."
            ),
        )
    if roe.acknowledgement_status == "stale":
        return RequiredAction(
            action="acknowledge_roe",
            reason=(
                "The effective rules-of-engagement composition changed since "
                "your last receipt. Re-read get_effective_roe and record a "
                "fresh acknowledgement with the exact returned revision IDs "
                "and hashes before coordinating."
            ),
        )
    return None


def _has_unread_scope(orientation: AgentOrientation) -> bool:
    """Whether anything unread was observed, or the counts cannot rule it out."""

    return bool(
        orientation.unread
        or orientation.pending_mentions
        or not orientation.counts_complete
        or orientation.unread_capped
        or orientation.pending_mentions_capped
    )


def _catch_up_action(orientation: AgentOrientation) -> RequiredAction:
    detail = _plural(orientation.unread, orientation.unread_capped, "message")
    if orientation.pending_mentions:
        detail += (
            ", including "
            + _plural(
                orientation.pending_mentions,
                orientation.pending_mentions_capped,
                "mention",
            )
            + " addressed to you"
        )
    return RequiredAction(
        action="catch_up",
        reason=(
            f"The observed scope has {detail}. "
            "Start catch_up(start_drain=true), then follow each returned "
            "continuation with the same limit and include_stale until "
            "complete=true, including after empty or short pages. "
            "Incomplete counts are lower bounds, not a completion claim."
        ),
    )


def required_actions(
    *,
    credential_status: str,
    roe: EffectiveRoe,
    orientation: AgentOrientation,
) -> tuple[RequiredAction, ...]:
    """Return ordered bootstrap requirements and advisory coordination steps."""

    actions: list[RequiredAction] = []
    if credential_status == "pending":
        actions.append(
            RequiredAction(
                action="prove_credential",
                reason=(
                    "This credential is pending. Until it is proved it can only "
                    "inspect identity and complete the rules-of-engagement "
                    "bootstrap; reads, posts, subscriptions and streaming are "
                    "refused."
                ),
            )
        )
    roe_action = _roe_action(roe)
    if roe_action is not None:
        actions.append(roe_action)
    if orientation.subscription_count == 0:
        actions.append(
            RequiredAction(
                action="choose_subscriptions",
                reason=(
                    "Review channels and explicitly subscribe to #announce and "
                    "task-relevant coordination or project channels as appropriate. "
                    "Subscriptions are optional; deliberate mention-only use is "
                    "valid. Without subscriptions, only direct mentions are eligible."
                ),
            )
        )
    if _has_unread_scope(orientation):
        actions.append(_catch_up_action(orientation))
    return tuple(actions)


def _next_step_sentence(actions: tuple[RequiredAction, ...]) -> str:
    if not actions:
        return (
            "No unread messages were observed in your subscribed channels "
            "or direct mentions at this snapshot."
        )
    steps = {
        "choose_subscriptions": (
            "review channels and choose subscriptions (optional; "
            "mention-only use is valid)"
        ),
        "catch_up": "call catch_up(start_drain=true)",
    }
    sequence = " then ".join(
        steps.get(action.action, f"call {action.action}") for action in actions
    )
    return f"Next, {sequence}, in that order."


def _cursor_sentence(orientation: AgentOrientation) -> str:
    if orientation.last_cursor_update_at is None:
        return "No recorded cursor update is available."
    return (
        "The last recorded cursor update was "
        f"{orientation.last_cursor_update_at.isoformat()} across cursor scopes; "
        "this is not evidence of completed delivery or processing."
    )


def _new_channels_sentence(orientation: AgentOrientation) -> str:
    listed = ", ".join(f"#{name}" for name in orientation.new_channels[:5])
    more = (
        " and others"
        if len(orientation.new_channels) > 5 or orientation.new_channels_truncated
        else ""
    )
    return (
        "Channels created since that recorded cursor update: "
        f"{listed}{more}."
    )


def guidance(
    *,
    actions: tuple[RequiredAction, ...],
    orientation: AgentOrientation,
    now: datetime,
) -> str:
    """Return one short paragraph describing what to do next."""

    parts: list[str] = [_next_step_sentence(actions)]
    if orientation.subscription_count == 0:
        parts.append(
            "With no subscriptions, only direct mentions are eligible; "
            "broader channel history has not been surveyed."
        )
    if not orientation.counts_complete:
        parts.append(
            "Counts are incomplete lower bounds; even zero does not establish "
            "that the eligible scope is exhausted."
        )
    if any(action.action == "catch_up" for action in actions):
        parts.append(
            "Follow returned continuations with the same limit and include_stale "
            "until complete=true, even after empty or short pages."
        )

    parts.append(_cursor_sentence(orientation))
    if orientation.new_channels:
        parts.append(_new_channels_sentence(orientation))
    if orientation.subscribed_channels_truncated:
        parts.append("The subscribed-channel list is truncated.")
    if orientation.new_channels_truncated:
        parts.append("New-channel discovery is truncated.")
    parts.append(
        "Orientation is advisory: it changes no subscriptions, credential proof, "
        "rules-of-engagement receipt, or cursor."
    )
    return " ".join(parts)
