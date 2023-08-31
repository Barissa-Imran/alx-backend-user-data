#!/usr/bin/env python3
"""
Module for filtering logs
"""
import re
from typing import List


patterns = {
    'exract': lambda x, y: r'(?p<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}
PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str
        ) -> str:
    """Filters a log line"""
    extract, replace = (patterns['exract'], patterns['replace'])
    return re.sub(extract(fields, separator), replace(redaction), message)
