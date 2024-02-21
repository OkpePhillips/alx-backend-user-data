#!/usr/bin/env python3
"""
Auth module with password hashing
"""

import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """ Initialise a db instance
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Registers a new user.
        """
        try:
            existing_user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            pass

        hashed_password = self._hash_password(password)
        user = self._db.add_user(email=email, hashed_password=hashed_password)

        return user

    @staticmethod
    def _hash_password(password: str) -> bytes:
        """
        Hashes a password string with salt using bcrypt
        """
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password
