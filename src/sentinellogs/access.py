from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

ROLES = frozenset({"admin", "soc_analyst", "auditor"})
PERMISSIONS = {
    "admin": frozenset({"events:read", "events:write", "alerts:manage", "reports:export", "audit:verify", "users:manage"}),
    "soc_analyst": frozenset({"events:read", "alerts:manage", "reports:export"}),
    "auditor": frozenset({"events:read", "reports:export", "audit:verify"}),
}


class IdentityProvider(Protocol):
    def authenticate(self, credentials: dict[str, Any]) -> "Principal | None":
        """Validate credentials through OIDC, SAML or LDAP/AD."""


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    roles: frozenset[str]
    claims: dict[str, Any] | None = None


class RoleMapper:
    def __init__(self, role_claim: str = "roles", default_role: str = "auditor") -> None:
        self.role_claim = role_claim
        self.default_role = default_role
        if default_role not in ROLES:
            raise ValueError(f"unsupported default role: {default_role}")

    def from_claims(self, claims: dict[str, Any], *, subject: str, tenant_id: str) -> Principal:
        raw_roles = claims.get(self.role_claim, claims.get("groups", []))
        if isinstance(raw_roles, str):
            raw_roles = [raw_roles]
        roles = frozenset(str(role).lower().replace(" ", "_") for role in raw_roles if str(role).lower().replace(" ", "_") in ROLES)
        return Principal(subject, tenant_id, roles or frozenset({self.default_role}), claims)


class AccessController:
    def __init__(self, providers: dict[str, IdentityProvider] | None = None, role_mapper: RoleMapper | None = None) -> None:
        self.providers = dict(providers or {})
        self.role_mapper = role_mapper or RoleMapper()

    def authenticate(self, provider: str, credentials: dict[str, Any]) -> Principal:
        if provider not in {"oidc", "oauth2", "saml", "ldap", "ad"}:
            raise ValueError(f"unsupported identity provider: {provider}")
        identity_provider = self.providers.get(provider)
        if identity_provider is None:
            raise ValueError(f"identity provider is not configured: {provider}")
        principal = identity_provider.authenticate(credentials)
        if principal is None:
            raise PermissionError("authentication failed")
        if not principal.roles:
            return self.role_mapper.from_claims(principal.claims or {}, subject=principal.subject, tenant_id=principal.tenant_id)
        return principal

    def authorize(self, principal: Principal, permission: str, tenant_id: str) -> bool:
        if principal.tenant_id != tenant_id:
            return False
        return any(permission in PERMISSIONS[role] for role in principal.roles if role in PERMISSIONS)