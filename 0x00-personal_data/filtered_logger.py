#!/usr/bin/env python3
"""
Module for filtering logs
"""
import re
import logging
from typing import List


patterns = {
    'extract': lambda x, y: r'(?p<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str
        ) -> str:
    """Filters a log line"""
    extract, replace = (patterns['extract'], patterns['replace'])
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """
    Creates a new logger for user data
    """
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger
