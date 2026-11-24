"""Production-oriented SQLite storage primitives."""

from __future__ import annotations

from strugglebus.store._common import (
    HUMAN_CHANNEL,
    HUMAN_OPERATOR_AGENT_ID,
    MAINTENANCE_SYSTEM_AGENT_ID,
    SYSTEM_AUTHOR_IDS,
    _audit_text,
    utc_now,
)
from strugglebus.store._access_freeze import AccessFreezeMixin
from strugglebus.store._core import CoreMixin
from strugglebus.store._credentials import CredentialMixin
from strugglebus.store._dashboard import DashboardMixin
from strugglebus.store._enrollment import EnrollmentMixin
from strugglebus.store._host_enrollment import HostEnrollmentMixin
from strugglebus.store._lifecycle import LifecycleMixin
from strugglebus.store._messages import MessagesMixin
from strugglebus.store._mobile import MobileMixin
from strugglebus.store._retention import RetentionMixin
from strugglebus.store._roe import RoeMixin
from strugglebus.store._service_principals import ServicePrincipalMixin
from strugglebus.store._site_documents import SiteDocumentMixin
from strugglebus.store._sites import SatelliteSiteMixin
from strugglebus.store._task_claims import TaskClaimsMixin


class SQLiteStore(
    CoreMixin,
    AccessFreezeMixin,
    RoeMixin,
    LifecycleMixin,
    EnrollmentMixin,
    ServicePrincipalMixin,
    HostEnrollmentMixin,
    CredentialMixin,
    MessagesMixin,
    TaskClaimsMixin,
    MobileMixin,
    RetentionMixin,
    SatelliteSiteMixin,
    SiteDocumentMixin,
    DashboardMixin,
):
    """Open a configured SQLite connection for each bounded operation."""


__all__ = [
    "HUMAN_CHANNEL",
    "HUMAN_OPERATOR_AGENT_ID",
    "MAINTENANCE_SYSTEM_AGENT_ID",
    "SQLiteStore",
    "SYSTEM_AUTHOR_IDS",
    "_audit_text",
    "utc_now",
]
