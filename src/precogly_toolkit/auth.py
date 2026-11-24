"""Explicit credentials for disposable local development; no network operations."""

from __future__ import annotations

import os
from collections.abc import Mapping

EMAIL_VAR = "LOCAL_PRECOGLY_EMAIL"
PASSWORD_VAR = "LOCAL_PRECOGLY_PASSWORD"


class MissingCredentialsError(RuntimeError):
    """No token or explicit local login credentials were configured."""


def local_login_payload(env: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if env is None else env
    email = source.get(EMAIL_VAR, "").strip()
    password = source.get(PASSWORD_VAR, "")
    if not email or not password:
        raise MissingCredentialsError(
            "PRECOGLY_TOKEN is not set and the local login variables are missing. "
            f"Set {EMAIL_VAR} and {PASSWORD_VAR} for a disposable localhost Precogly "
            "instance (never a shared or deployed one), or export PRECOGLY_TOKEN."
        )
    return {"email": email, "password": password}
