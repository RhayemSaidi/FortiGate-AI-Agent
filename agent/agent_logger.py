# agent/agent_logger.py

import logging
import json
import os
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

def get_agent_logger(name: str = "fortigate_agent") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # File handler — DEBUG level, structured JSON
    fh = logging.FileHandler(os.path.join(LOG_DIR, "agent_debug.log"), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '{"ts":"%(asctime)s","level":"%(levelname)s","module":"%(module)s",'
        '"line":%(lineno)d,"msg":%(message)s}'
    ))

    # Console handler — WARNING+ only, human-readable
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter('[%(levelname)s] %(module)s: %(message)s'))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

logger = get_agent_logger()
