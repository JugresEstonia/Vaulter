import structlog, sys

def get_logger(debug: bool = False):
    """Return a structlog logger that writes JSON to stderr."""
    processors = [
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.dict_tracebacks,
        structlog.processors.JSONRenderer(),
    ]

    if not debug:
        def _filter_secrets(_, __, event_dict):
            event_dict.pop("secret", None)
            event_dict.pop("password", None)
            event_dict.pop("key", None)
            return event_dict
        processors = [_filter_secrets] + processors

    structlog.configure(
        processors=processors,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )
    return structlog.get_logger()
