from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict


class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


@dataclass
class Request:
    headers: Dict[str, str] | None = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}


@dataclass
class Response:
    content: Any = None
    media_type: str | None = None


class FastAPI:
    def __init__(self, *args, **kwargs):
        self.routes = []

    def _route(self, method: str, path: str):
        def deco(fn: Callable):
            self.routes.append((method, path, fn))
            return fn
        return deco

    def get(self, path: str):
        return self._route("GET", path)

    def post(self, path: str):
        return self._route("POST", path)

    def delete(self, path: str):
        return self._route("DELETE", path)

    def exception_handler(self, exc_type):
        def deco(fn: Callable):
            return fn
        return deco
