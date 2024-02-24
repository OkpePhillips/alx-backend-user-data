#!/usr/bin/env python3
"""
Session Authentication module
"""

from api.v1.auth.auth import Auth
import uuid
import os


class SessionAuth(Auth):
    """
    Session Auth class definition
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Function creates a Session ID for a user_id
        """
        if user_id is None or not isinstance(user_id, str):
            return None

        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Function a class attribute user_id_by_session_id initialized
        by an empty dictionary
        """
        if session_id is None or not isinstance(session_id, str):
            return None

        return self.user_id_by_session_id.get(session_id)

    def session_cookie(self, request=None):
        """
        Method returns a cookie value from a request
        """
        if request is None:
            return None

        session_name = os.getenv("SESSION_NAME", "_my_session_id")
        return request.cookies.get(session_name)

    def current_user(self, request=None):
        """
        Returning current user based on cookie value
        """
        if request is None:
            return None
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if user_id:
            return User.get(user_id)
        return None

    def destroy_session(self, request=None) -> bool:
        """
        Function to destroy the session
        """
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if session_id is None:
            return False
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False
        del self.user_id_by_session_id[session_id]
        return True
