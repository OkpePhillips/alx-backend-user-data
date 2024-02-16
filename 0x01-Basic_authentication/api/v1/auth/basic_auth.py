#!/usr/bin/env python3
"""
Basic Auth module
"""
import base64
from typing import TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """
    Basic auth class that inherits from Auth
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Returns Base64 part of the Authorization header for
        a Basic Authentication
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header.split(' ')[1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """
        Method that returns the decoded value of a Base64 string
        base64_authorization_header
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            bytes_value = base64.b64decode(base64_authorization_header)
            decoded_value = bytes_value.decode('utf-8')
            return decoded_value
        except base64.binascii.Error:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str, str):
        """
        Method returns the user email and password from
        the Base64 decoded value
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        user_email, user_password = decoded_base64_authorization_header. \
            split(':', 1)
        return user_email, user_password

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Returns the User instance based on his email and password
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        user_instances = User.search({"email": user_email})
        if user_instances is None:
            return None
        for user in user_instances:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Method retrieves the User instance for a request
        """
        if request is None:
            return None

        authorization_header = request.headers.get('Authorization')
        if authorization_header is None:
            return None

        base64_authorization_header = self.extract_base64_authorization_header(
                authorization_header)
        if base64_authorization_header is None:
            return None

        decoded_authorization_header = self.decode_base64_authorization_header(
                base64_authorization_header)
        if decoded_authorization_header is None:
            return None

        user_email, user_pwd = self.extract_user_credentials(
                decoded_authorization_header)
        if user_email is None or user_pwd is None:
            return None

        return self.user_object_from_credentials(user_email, user_pwd)
