#!/usr/bin/env python3
"""
Defines a hash_password function to return a hashed password

"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    This returns a hashed password
    Args:
        password (str): password to be hashed
    """
    q = password.encode()
    hashed = hashpw(q, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check whether a password is valid
    Args:
        hashed_password (bytes): hashed and encrypted password
        password (str): password in string
    Return:
        bool
    """
    return bcrypt.checkpw(password.encode(), hashed_password)