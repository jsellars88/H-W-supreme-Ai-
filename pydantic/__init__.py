from __future__ import annotations


class BaseModel:
    def __init__(self, **kwargs):
        for key, val in kwargs.items():
            setattr(self, key, val)


def Field(default=None, **kwargs):
    return default
