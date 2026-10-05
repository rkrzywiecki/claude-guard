"""structlog configuration: JSON lines on stderr.

stderr keeps stdout free for hook responses and `scan --json` output. Loggers are not cached,
so the factory runs per call and always writes to the current `sys.stderr`.
"""

import logging
import sys
from typing import Any

import structlog


def _stderr_logger(*_: Any) -> structlog.PrintLogger:
    return structlog.PrintLogger(sys.stderr)


def configure_logging(level: str = "INFO") -> None:
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=_stderr_logger,
        cache_logger_on_first_use=False,
    )
