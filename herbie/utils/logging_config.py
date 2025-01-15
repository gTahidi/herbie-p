"""
Logging configuration for Herbie.
"""
import logging
import sys
from pathlib import Path

def setup_logging(console_level=logging.INFO, file_level=logging.DEBUG):
    """Set up logging configuration."""
    # Get the root logger
    logger = logging.getLogger('herbie')
    
    # If logger already has handlers, assume it's configured
    if logger.hasHandlers():
        return logger
    
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Create formatters
    console_formatter = logging.Formatter('%(message)s')
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    file_handler = logging.FileHandler(log_dir / 'herbie.log')
    file_handler.setLevel(file_level)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger

def log_separator(logger, message, level=logging.INFO):
    """Log a separator line with a message."""
    separator = "=" * 50
    logger.log(level, f"\n{separator}")
    logger.log(level, message)
    logger.log(level, f"{separator}\n")
