"""Central logging with rotation and secret redaction.

Log records pass through :class:`SecretFilter` so an API key, bearer token or
other credential accidentally logged by a caller never reaches disk.
"""
from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

DEFAULT_LOG_DIR = Path("storage/logs")
LOG_FILE_NAME = "ase.log"

_REDACTION_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-]{8,})"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[=:]\s*)([^\s,;\"']{6,})"),
    re.compile(r"([A-Za-z0-9_\-]{43,})"),
)


class SecretFilter(logging.Filter):
    """Replace credential-shaped substrings with a placeholder."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        redacted = message
        for pattern in _REDACTION_PATTERNS:
            redacted = pattern.sub(lambda match: match.group(1) + "<redacted>", redacted)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def get_logger(name="ASE", log_dir=None, level="INFO", max_bytes=5 * 1024 * 1024, backups=3):
    """Return a logger writing to a rotating file plus stderr."""
    logger = logging.getLogger(name)
    if getattr(logger, "_ase_configured", False):
        return logger

    directory = Path(log_dir) if log_dir else DEFAULT_LOG_DIR
    directory.mkdir(parents=True, exist_ok=True)

    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    try:
        file_handler = RotatingFileHandler(
            directory / LOG_FILE_NAME,
            maxBytes=max_bytes,
            backupCount=backups,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(SecretFilter())
        logger.addHandler(file_handler)
    except OSError:
        # A read-only filesystem must not stop the engine from running.
        pass

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.addFilter(SecretFilter())
    logger.addHandler(console)

    logger._ase_configured = True
    return logger


def reset_loggers():
    """Detach handlers. Used by tests that point the engine at temp dirs."""
    for name in list(logging.Logger.manager.loggerDict):
        if not name.startswith("ASE"):
            continue
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            try:
                handler.close()
            except Exception:
                pass
            logger.removeHandler(handler)
        logger._ase_configured = False
