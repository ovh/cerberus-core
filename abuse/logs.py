import logging


def setup_loggers(app):
    """Setup loggers for a production environment"""
    # Flask lazily initializes its logger, it must be called here so we can
    # change its configuration
    _ = app.logger

    for logger_name in ("", app.name, "rq"):
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.DEBUG)

        # Clean all existing handlers
        logger.handlers = list()

    # Add our handlers
    for handler in get_handlers_from_config(app.config["LOGGERS"]):
        logging.getLogger().addHandler(handler)


def get_handlers_from_config(config):
    """Read config['LOGGERS'] and generate the corresponding handlers"""
    handlers = list()
    for handler_type, handler_config in config.items():
        handler = None
        if handler_type == "syslog":
            handler = _get_syslog_handler(handler_config)
        elif handler_type == "stdout":
            handler = _get_stdout_handler(handler_config)
        elif handler_type == "file":
            handler = _get_file_handler(handler_config)

        if handler:
            handler.setLevel(getattr(logging, handler_config["level"].upper()))
            handlers.append(handler)

    return handlers


def _get_syslog_handler(logger_config):
    """Get a syslog handler.

    If 'device' is set it will use this device as syslog address,
    otherwise it will send to 'host':'port' using either TCP or UDP as
    defined in 'transport'.
    """
    from logging.handlers import SysLogHandler
    from socket import SOCK_DGRAM, SOCK_STREAM

    if logger_config.get("device", False):
        return SysLogHandler(address=logger_config["device"])
    address = (logger_config["host"], logger_config["port"])
    socktype = SOCK_STREAM
    if logger_config["transport"] == "UDP":
        socktype = SOCK_DGRAM
    handler = SysLogHandler(
        address=address, socktype=socktype, facility=SysLogHandler.LOG_USER
    )
    return handler


def _get_stdout_handler(logger_config):
    from logging import StreamHandler
    from sys import stdout

    handler = StreamHandler(stream=stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    return handler


def _get_file_handler(logger_config):
    from logging.handlers import RotatingFileHandler

    handler = RotatingFileHandler(
        filename=logger_config["file_name"],
        maxBytes=logger_config["max_bytes"],
        backupCount=logger_config["backups"],
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    return handler


class TaskLoggerAdapter(logging.LoggerAdapter):
    """LoggerAdapter to be used within tasks."""

    def process(self, msg, kwargs):
        data = dict()

        task = kwargs.pop("task", None)
        if task:
            data.update(
                {
                    "task_id": getattr(task, "id", None),
                    "task_name": getattr(task, "name", None),
                    "task_args": getattr(task, "args", None),
                    "task_kwargs": getattr(task, "kwargs", None),
                }
            )

        extra = kwargs.setdefault("extra", {})
        for key in data:
            extra.setdefault(key, data[key])

        return msg, kwargs
