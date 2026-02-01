"""
Logging Module
Configures application-wide logging with rotation.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys

from utils.config import LOG_LEVEL, LOG_FORMAT, LOG_ROTATION_SIZE, LOG_BACKUP_COUNT, LOGS_PATH


def setup_logging(log_level: str = LOG_LEVEL, log_file: Path = None) -> logging.Logger:
    """
    Setup application-wide logging.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (default: logs/app.log)
        
    Returns:
        Root logger instance
    """
    # Create logs directory
    LOGS_PATH.mkdir(parents=True, exist_ok=True)
    
    if log_file is None:
        log_file = LOGS_PATH / 'app.log'
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=LOG_ROTATION_SIZE,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)  # Log everything to file
    file_formatter = logging.Formatter(LOG_FORMAT)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    logger.info("="*60)
    logger.info("Logging configured")
    logger.info(f"Level: {log_level}")
    logger.info(f"File: {log_file}")
    logger.info("="*60)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get logger for module.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)
