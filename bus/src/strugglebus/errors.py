"""Application-specific exceptions with safe, non-secret messages."""


class StrugglebusError(Exception):
    """Base class for expected Strugglebus failures."""


class ConfigurationError(StrugglebusError):
    """Application configuration is unsafe or incomplete."""


class TrustAnchorError(StrugglebusError):
    """Configured public CA publication is unavailable or invalid."""


class StorageError(StrugglebusError):
    """SQLite storage could not be initialized or used safely."""


class InsufficientStorageError(StorageError):
    """The disk holding the database is too full to accept more messages."""


class MigrationError(StorageError):
    """A database migration could not be validated or applied."""


class BackupError(StorageError):
    """A database backup could not be created or verified."""


class DatabaseVersionError(MigrationError):
    """The database schema version is unsupported."""


class MissingMigrationError(MigrationError):
    """The ordered migration set is incomplete."""


class DuplicateAgentNameError(StorageError):
    """An agent name is already registered."""


class AgentNotFoundError(StorageError):
    """An agent identity does not exist."""


class AgentAccessFrozenError(StorageError):
    """Agent access is blocked by the persistent emergency freeze."""


class CredentialConflictError(StorageError):
    """A credential lifecycle request conflicts with current state."""


class CredentialLimitError(StorageError):
    """A credential lifecycle safety limit was reached."""


class CredentialNotFoundError(StorageError):
    """A credential does not exist or is not available."""


class EnrollmentInvalidError(StorageError):
    """An enrollment token is unknown, expired, spent, or revoked."""


class EnrollmentExpiredError(EnrollmentInvalidError):
    """The right enrollment token was presented, after its time ran out."""


class EnrollmentNotFoundError(StorageError):
    """An enrollment does not exist."""


class ServicePrincipalNotFoundError(StorageError):
    """A service principal does not exist."""


class RoeConflictError(StorageError):
    """An RoE publication or acknowledgement conflicts with current state."""


class RoeAcknowledgementRequiredError(StorageError):
    """The current effective RoE composition has not been acknowledged."""


class DuplicateChannelNameError(StorageError):
    """A channel name is already registered."""


class ChannelLimitError(StorageError):
    """The configured channel capacity has been reached."""


class ChannelNotFoundError(StorageError):
    """A channel does not exist."""


class ReplyNotFoundError(StorageError):
    """A requested reply target does not exist."""


class MessageNotFoundError(StorageError):
    """A message does not exist."""


class MessageNotClaimableError(StorageError):
    """Only task messages can be claimed."""


class MessageClaimNotFoundError(StorageError):
    """A message has no current claim."""


class MessageClaimConflictError(StorageError):
    """A message is claimed by a different agent."""

    def __init__(self, message: str, claim: object) -> None:
        super().__init__(message)
        self.claim = claim


class PostRequestConflictError(StorageError):
    """A post retry key is already bound to different accepted input."""


class DomainValidationError(StrugglebusError):
    """A domain value violates the public application contract."""


class CatchUpUnavailableError(DomainValidationError):
    """A bounded drain expired or is unavailable after a process restart."""


class CatchUpCapacityError(DomainValidationError):
    """The bounded drain registry cannot admit another snapshot."""


class MessageTooLargeError(DomainValidationError):
    """A message body exceeds the configured byte limit."""


class UnknownMentionError(DomainValidationError):
    """A message references an unknown or inactive agent."""
