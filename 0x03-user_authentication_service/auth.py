#!/usr/bin/env python3
"""
Auth module with password hashing
"""

import bcrypt
import uuid
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User


def _generate_uuid() -> str:
    """
    Generate a string representation of a new UUID.
    """
    return str(uuid.uuid4())


def _hash_password(password: str) -> bytes:
    """
    Hashes a password string with salt using bcrypt
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


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

        hashed_password = _hash_password(password)
        user = self._db.add_user(email=email, hashed_password=hashed_password)

        return user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Check if the login credentials are valid.
        """
        try:
            user = self._db.find_user_by(email=email)
            hashed_password = user.hashed_password
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
        Create a session for the user and return the session ID.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except ValueError:
            return None

    def get_user_from_session_id(self, session_id: str) -> None:
        """
        Get the user corresponding to the given session ID.
        """
        if session_id:
            try:
                user = self._db.find_user_by(session_id=session_id)
                return user
            except NoResultFound:
                return None
        else:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroy the session for the user with the given user ID.
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            pass
        return None

    def get_reset_password_token(self, email: str) -> str:
        """
        Generate a reset password token for the user with the given email.
        """
        user = self._db.find_user_by(email=email)
        if user:
            reset_token = str(uuid.uuid4())
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        else:
            raise ValueError(f"User with email '{email}' does not exist.")

    def update_password(self, reset_token: str, new_password: str) -> None:
        """
        Update user's password using reset token.
        """
        user = self._db.find_user_by(reset_token=reset_token)
        if user:
            hashed_password = _hash_password(new_password)
            self._db.update_user(user.id, hashed_password=hashed_password,
                                 reset_token=None)
        else:
            raise ValueError("Reset token does not exist.")
