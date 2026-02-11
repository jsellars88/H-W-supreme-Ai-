from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class JSONResponse:
    status_code: int
    content: Any


@dataclass
class PlainTextResponse:
    content: str
    media_type: str = "text/plain"
