"""ASE exception hierarchy.

All engine errors derive from :class:`ASEError` so callers can catch one type
without masking unrelated programming errors.
"""


class ASEError(Exception):
    """Base exception for ASE."""


class ASEModuleError(ASEError):
    """Module registration or lifecycle error."""


class ASEConfigError(ASEError, ValueError):
    """Configuration validation error."""


class ASEEngineError(ASEError):
    """Engine lifecycle error."""


class ASEDatabaseError(ASEError):
    """Database open, migration or query error."""


class ASEScanError(ASEError):
    """Antivirus scan error."""


class ASEQuarantineError(ASEError):
    """Quarantine or restore error."""


class ASEIntelligenceError(ASEError, ValueError):
    """Threat intelligence validation error."""


class ASEThreatFeedError(ASEError):
    """Signed feed verification error."""


class ASEAPIAuthError(ASEError):
    """API authentication or authorization error."""
