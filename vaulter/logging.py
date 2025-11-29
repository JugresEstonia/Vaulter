import structlog, sys, pathlib, os

_LOG_STREAM = None

def _log_handle():
    """Open (or reuse) the secure log file handle stored under ~/.local/state/vaulter."""
    global _LOG_STREAM
    if _LOG_STREAM is None:
        default_path = pathlib.Path(os.environ.get("VAULTER_LOG", pathlib.Path.home() / ".local" / "state" / "vaulter" / "vaulter.log"))
        default_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(default_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.chmod(default_path, 0o600)
        _LOG_STREAM = os.fdopen(fd, "a", buffering=1)
    return _LOG_STREAM

def _human_renderer(_, __, event_dict):
    """Render structlog event dictionaries into human-readable timestamped lines."""
    ts = event_dict.pop("timestamp", "")
    level = event_dict.pop("level", "").upper()
    event = event_dict.pop("event", "")
    extras = " ".join(f"{k}={event_dict[k]}" for k in sorted(event_dict))
    return f"{ts} [{level}] {event} {extras}".strip()

def get_logger(debug: bool = False):
    """Return a structlog logger; stderr in debug, otherwise ~/.local/state/vaulter/."""
    processors = [
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.dict_tracebacks,
        _human_renderer,
    ]

    if not debug:
        def _filter_secrets(_, __, event_dict):
            event_dict.pop("secret", None)
            event_dict.pop("password", None)
            event_dict.pop("key", None)
            return event_dict
        processors = [_filter_secrets] + processors
        target = _log_handle()
    else:
        target = sys.stderr

    structlog.configure(
        processors=processors,
        logger_factory=structlog.PrintLoggerFactory(file=target),
    )
    return structlog.get_logger()
