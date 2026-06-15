"""
NetSight - Logging System (MODULE 11)
============================================
Configures structured logging with rotating file handlers for both
system events and alert events. Provides separate loggers for different
components to enable granular log management.

Purpose:
    - Centralized logging configuration
    - Separate log files for system events and security alerts
    - Rotating file handlers to prevent disk space exhaustion
    - Consistent log format across all modules

Log Format:
    [TIMESTAMP] [SEVERITY] [MODULE] MESSAGE
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from config import SYSTEM_LOG_FILE, ALERTS_LOG_FILE, LOG_MAX_BYTES, LOG_BACKUP_COUNT, LOGS_DIR

# Ensure logs directory exists
os.makedirs(LOGS_DIR, exist_ok=True)

# ============================================================
# LOG FORMAT
# ============================================================
LOG_FORMAT = '[%(asctime)s] [%(levelname)-8s] [%(name)-20s] %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# ============================================================
# FORMATTERS
# ============================================================
_formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)


def _create_file_handler(filepath, max_bytes=LOG_MAX_BYTES, backup_count=LOG_BACKUP_COUNT):
    """
    Create a rotating file handler with consistent formatting.

    Args:
        filepath: Path to the log file
        max_bytes: Maximum size of each log file before rotation
        backup_count: Number of rotated backup files to keep

    Returns:
        RotatingFileHandler configured with the standard formatter
    """
    handler = RotatingFileHandler(
        filepath,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    handler.setFormatter(_formatter)
    return handler


def _create_console_handler():
    """
    Create a console handler for development mode output.

    Returns:
        StreamHandler configured with the standard formatter
    """
    handler = logging.StreamHandler()
    handler.setFormatter(_formatter)
    return handler


# ============================================================
# SYSTEM LOGGER
# ============================================================
def get_system_logger(module_name='NetSight'):
    """
    Get a logger for system events (startup, shutdown, errors, info).

    Args:
        module_name: Name of the module requesting the logger

    Returns:
        Logger instance configured to write to system.log and console

    Usage:
        logger = get_system_logger('PacketSniffer')
        logger.info('Capture started on interface eth0')
        logger.error('Failed to initialize sniffer: %s', error)
    """
    logger = logging.getLogger(f'system.{module_name}')

    # Avoid adding duplicate handlers
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        logger.addHandler(_create_file_handler(SYSTEM_LOG_FILE))
        logger.addHandler(_create_console_handler())
        logger.propagate = False

    return logger


# ============================================================
# ALERT LOGGER
# ============================================================
def get_alert_logger(module_name='AlertManager'):
    """
    Get a logger for security alert events.

    Args:
        module_name: Name of the detection module generating alerts

    Returns:
        Logger instance configured to write to alerts.log and console

    Usage:
        logger = get_alert_logger('PortScanDetector')
        logger.warning('Port scan detected from 192.168.1.100 - 45 ports in 5s')
        logger.critical('Brute force attack on SSH from 10.0.0.5 - 150 attempts')
    """
    logger = logging.getLogger(f'alerts.{module_name}')

    # Avoid adding duplicate handlers
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        logger.addHandler(_create_file_handler(ALERTS_LOG_FILE))
        logger.addHandler(_create_console_handler())
        logger.propagate = False

    return logger


# ============================================================
# LOG HELPER FUNCTIONS
# ============================================================
def log_system_event(module, level, message, *args):
    """
    Quick helper to log a system event without obtaining a logger instance.

    Args:
        module: Module name string
        level: Log level string ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        message: Log message (may contain %s format specifiers)
        *args: Arguments for format specifiers
    """
    logger = get_system_logger(module)
    log_func = getattr(logger, level.lower(), logger.info)
    log_func(message, *args)


def log_alert_event(module, level, message, *args):
    """
    Quick helper to log a security alert event.

    Args:
        module: Detection module name string
        level: Log level string ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        message: Alert message (may contain %s format specifiers)
        *args: Arguments for format specifiers
    """
    logger = get_alert_logger(module)
    log_func = getattr(logger, level.lower(), logger.warning)
    log_func(message, *args)


# ============================================================
# INITIALIZATION
# ============================================================
# Create a root system logger on import
_root_logger = get_system_logger('System')
_root_logger.info('NetSight Logging System initialized')
_root_logger.info('System log: %s', SYSTEM_LOG_FILE)
_root_logger.info('Alerts log: %s', ALERTS_LOG_FILE)
