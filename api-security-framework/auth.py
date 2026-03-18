"""
auth.py
-------
Handles JWT and session-based authentication for the ZAP scanner.
Tokens can be provided via config.yml or environment variables:
  - API_JWT_TOKEN      : JWT bearer token
  - API_SESSION_COOKIE : session cookie value
"""

import os
import logging

logger = logging.getLogger(__name__)


class AuthHandler:
    """
    Configures ZAP to inject authentication headers or cookies
    into every request during the scan.
    """

    def __init__(self, zap, config: dict):
        self.zap = zap
        self.config = config
        self.auth_cfg = config.get("auth", {})

    def is_enabled(self) -> bool:
        return self.auth_cfg.get("enabled", False)

    def get_auth_type(self) -> str:
        return self.auth_cfg.get("type", "none").lower()

    # ── JWT ───────────────────────────────────────────────────────────────────

    def _get_jwt_token(self) -> str:
        """Resolve JWT from env var first, then config."""
        token = os.environ.get("API_JWT_TOKEN", "").strip()
        if not token:
            token = self.auth_cfg.get("jwt", {}).get("token", "").strip()
        if not token:
            logger.warning("JWT auth enabled but no token found. "
                           "Set API_JWT_TOKEN env var or config.yml jwt.token.")
        return token

    def _configure_jwt(self):
        jwt_cfg = self.auth_cfg.get("jwt", {})
        header = jwt_cfg.get("header", "Authorization")
        prefix = jwt_cfg.get("prefix", "Bearer ")
        token = self._get_jwt_token()

        if not token:
            return False

        full_value = f"{prefix}{token}"
        try:
            self.zap.replacer.add_rule(
                description="JWT Auth Header",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring=header,
                replacement=full_value,
                initiators="",
            )
            logger.info("JWT auth configured — header: %s", header)
            return True
        except Exception as e:
            logger.error("Failed to configure JWT in ZAP: %s", e)
            return False

    # ── Session Cookie ────────────────────────────────────────────────────────

    def _get_session_cookie(self) -> str:
        """Resolve session cookie from env var first, then config."""
        cookie = os.environ.get("API_SESSION_COOKIE", "").strip()
        if not cookie:
            cookie = self.auth_cfg.get("session", {}).get("cookie_value", "").strip()
        if not cookie:
            logger.warning("Session auth enabled but no cookie found. "
                           "Set API_SESSION_COOKIE env var or config.yml session.cookie_value.")
        return cookie

    def _configure_session(self):
        session_cfg = self.auth_cfg.get("session", {})
        cookie_name = session_cfg.get("cookie_name", "session")
        cookie_value = self._get_session_cookie()

        if not cookie_value:
            return False

        try:
            self.zap.replacer.add_rule(
                description="Session Cookie",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Cookie",
                replacement=f"{cookie_name}={cookie_value}",
                initiators="",
            )
            logger.info("Session cookie auth configured — cookie: %s", cookie_name)
            return True
        except Exception as e:
            logger.error("Failed to configure session cookie in ZAP: %s", e)
            return False

    # ── Public Interface ──────────────────────────────────────────────────────

    def configure(self) -> bool:
        """
        Apply auth configuration to ZAP based on config type.
        Returns True if at least one auth method was configured successfully.
        """
        if not self.is_enabled():
            logger.info("Auth disabled — scanning without authentication.")
            return True

        auth_type = self.get_auth_type()
        logger.info("Configuring auth type: %s", auth_type)

        if auth_type == "jwt":
            return self._configure_jwt()

        elif auth_type == "session":
            return self._configure_session()

        elif auth_type == "both":
            jwt_ok = self._configure_jwt()
            session_ok = self._configure_session()
            return jwt_ok or session_ok

        else:
            logger.info("Auth type '%s' not recognized — skipping.", auth_type)
            return True

    def get_auth_headers(self) -> dict:
        """
        Returns auth headers as a plain dict — useful for direct requests
        (e.g. spider seed requests) outside of ZAP replacer rules.
        """
        headers = {}
        auth_type = self.get_auth_type()

        if auth_type in ("jwt", "both"):
            jwt_cfg = self.auth_cfg.get("jwt", {})
            prefix = jwt_cfg.get("prefix", "Bearer ")
            token = self._get_jwt_token()
            if token:
                header = jwt_cfg.get("header", "Authorization")
                headers[header] = f"{prefix}{token}"

        if auth_type in ("session", "both"):
            session_cfg = self.auth_cfg.get("session", {})
            name = session_cfg.get("cookie_name", "session")
            value = self._get_session_cookie()
            if value:
                headers["Cookie"] = f"{name}={value}"

        return headers
