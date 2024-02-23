#!/usr/bin/env python3
"""
Auth module containing the auth class
"""

from typing import List, TypeVar
from flask import request


class Auth:
    """
    Auth base class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determine which paths need authentication
        """
        if path is None or not excluded_paths:
            return True
        path = path.rstrip('/')
        excluded_paths = [p.rstrip('/') for p in excluded_paths]
        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        """
        Parses the authorization header
        """
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Method to return the current user if verified
        """
        return None
