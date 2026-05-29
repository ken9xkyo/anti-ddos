#!/usr/bin/env python3
import json
import urllib.error
import urllib.request
from typing import Any


class APIError(RuntimeError):
    def __init__(self, method: str, path: str, status: int, body: str):
        super().__init__(f"{method} {path} returned {status}: {body}")
        self.method = method
        self.path = path
        self.status = status
        self.body = body


class ApiClient:
    def __init__(self, base_url: str, timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.token = ""

    def login(self, username: str, password: str) -> dict[str, Any]:
        session = self.request(
            "POST",
            "/v1/auth/login",
            {"username": username, "password": password},
            authenticated=False,
        )
        self.token = session["token"]
        return session

    def with_token(self, token: str) -> "ApiClient":
        clone = ApiClient(self.base_url, self.timeout)
        clone.token = token
        return clone

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: Any, *, headers: dict[str, str] | None = None) -> Any:
        return self.request("POST", path, payload, headers=headers)

    def patch(self, path: str, payload: Any, *, headers: dict[str, str] | None = None) -> Any:
        return self.request("PATCH", path, payload, headers=headers)

    def put(self, path: str, payload: Any, *, headers: dict[str, str] | None = None) -> Any:
        return self.request("PUT", path, payload, headers=headers)

    def delete(self, path: str, *, reason: str = "") -> Any:
        headers = {"X-Audit-Reason": reason} if reason else None
        return self.request("DELETE", path, headers=headers)

    def agent_post(self, path: str, token: str, payload: Any) -> Any:
        return self.request("POST", path, payload, authenticated=False, headers={"Authorization": f"Bearer {token}"})

    def request(
        self,
        method: str,
        path: str,
        payload: Any | None = None,
        *,
        authenticated: bool = True,
        headers: dict[str, str] | None = None,
    ) -> Any:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=body, method=method)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if authenticated and self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                text = response.read().decode("utf-8")
                if not text:
                    return None
                return json.loads(text)
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            raise APIError(method, path, exc.code, body_text) from exc

