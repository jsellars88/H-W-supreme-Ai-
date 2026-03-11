from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IdentityContext:
    actor_id: str
    tenant_id: str


class AuthStub:
    """Minimal identity/auth stub.

    Accepts any non-empty actor and tenant values.
    """

    def validate(self, actor_id: str, tenant_id: str) -> IdentityContext:
        if not actor_id or not tenant_id:
            raise ValueError("Invalid identity context")
        return IdentityContext(actor_id=actor_id, tenant_id=tenant_id)
