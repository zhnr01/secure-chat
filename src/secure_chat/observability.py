"""Logging setup shared by the server and client."""
import logging


def setup_logger(name: str = "secure_chat", level: int = logging.INFO) -> logging.Logger:
    """Return a configured logger, creating a stream handler exactly once."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(level)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger
