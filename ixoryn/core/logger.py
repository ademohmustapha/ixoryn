"""Ixoryn Logger - Centralized logging with file and console output."""

import logging
import os
from pathlib import Path
from datetime import datetime


def get_logger(name: str = "ixoryn") -> logging.Logger:
    log_dir = Path.home() / ".ixoryn" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"ixoryn_{datetime.now().strftime('%Y%m%d')}.log"

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))

    logger.addHandler(fh)
    return logger
