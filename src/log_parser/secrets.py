from __future__ import annotations

import os
from abc import ABC, abstractmethod


class SecretProvider(ABC):
    """Abstract provider for secrets used by sinks and alert integrations."""

    @abstractmethod
    def get_secret(self, name: str) -> str:
        """Return a secret value by logical name."""


class EnvSecretProvider(SecretProvider):
    """Default provider backed by environment variables."""

    def __init__(self, env: dict[str, str] | None = None) -> None:
        self._env = os.environ if env is None else env

    def get_secret(self, name: str) -> str:
        value = self._env.get(name)
        if value is None:
            raise KeyError(f"Missing secret '{name}'")
        return value


class VaultSecretProvider(SecretProvider):
    """Stub interface ready for a real Vault backend integration."""

    def get_secret(self, name: str) -> str:
        raise NotImplementedError("Vault integration is not implemented in this package yet")


class AWSSecretsManagerProvider(SecretProvider):
    """Stub interface ready for AWS Secrets Manager integration."""

    def get_secret(self, name: str) -> str:
        raise NotImplementedError("AWS Secrets Manager integration is not implemented in this package yet")
