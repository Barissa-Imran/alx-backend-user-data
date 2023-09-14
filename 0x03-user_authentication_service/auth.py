#!/usr/bin/env python3
"""Authentication module"""
import bcrypt
from db import DB


def _hash_password(password: str) -> str:
    """Returns a salted hash of the input password"""
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed