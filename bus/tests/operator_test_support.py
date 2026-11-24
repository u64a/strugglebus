"""Explicit authenticated fixtures; default application fixtures stay disabled."""

from contextlib import contextmanager
from functools import lru_cache
import re
from unittest.mock import patch

from fastapi.testclient import TestClient

from strugglebus.operator_auth import PasswordVerifier, create_password_verifier


PASSWORD = "synthetic integration operator password"


@lru_cache(maxsize=1)
def verifier() -> PasswordVerifier:
    return PasswordVerifier.parse(create_password_verifier(PASSWORD))


def csrf(response) -> str:
    assert response.status_code == 200, response.text
    match = re.search(r'name="csrf" value="([^"]+)"', response.text)
    assert match is not None
    return match[1]


class OperatorClient(TestClient):
    operator_csrf: str

    def register(self, name: str, description: str = ""):
        return self.post(
            "/register",
            data={"csrf": self.operator_csrf, "name": name, "description": description},
            headers={"Origin": str(self.base_url).rstrip("/")},
        )


@contextmanager
def operator_client(application, *, base_url="https://bus.lan"):
    with (
        patch("strugglebus.operator_auth.load_password_verifier", return_value=verifier()),
        OperatorClient(application, base_url=base_url, follow_redirects=False) as client,
    ):
        challenge = csrf(client.get("/login"))
        response = client.post(
            "/login", data={"csrf": challenge, "password": PASSWORD},
            headers={"Origin": base_url},
        )
        assert response.status_code == 303, response.text
        client.operator_csrf = csrf(client.get("/operator/session"))
        yield client
