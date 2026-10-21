from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import jwt

if TYPE_CHECKING:
    from fixtures.common_types import TenantId


@dataclass
class AuthKeys:
    priv: str

    def generate_token(
        self,
        *,
        scope: TokenScope,
        exp: int | None = None,
        iat: int | None = None,
        **token_data: Any,
    ) -> str:
        """
        Signs `{"scope": scope, **token_data}`. The other claims are strings; `exp` and
        `iat`, when given, stay numeric (RFC 7519 NumericDate, seconds since the epoch).
        """
        claims: dict[str, Any] = {key: str(val) for key, val in token_data.items()}
        for name, value in (("exp", exp), ("iat", iat)):
            if value is not None:
                claims[name] = int(value)
        token = jwt.encode({"scope": scope, **claims}, self.priv, algorithm="EdDSA")
        # cast(Any, self.priv)

        # jwt.encode can return 'bytes' or 'str', depending on Python version or type
        # hinting or something (not sure what). If it returned 'bytes', convert it to 'str'
        # explicitly.
        if isinstance(token, bytes):
            token = token.decode()

        return token

    def generate_pageserver_token(self) -> str:
        return self.generate_token(scope=TokenScope.PAGE_SERVER_API)

    def generate_safekeeper_token(self) -> str:
        return self.generate_token(scope=TokenScope.SAFEKEEPER_DATA)

    # generate token giving access to only one tenant
    def generate_tenant_token(self, tenant_id: TenantId) -> str:
        return self.generate_token(scope=TokenScope.TENANT, tenant_id=str(tenant_id))


class TokenScope(StrEnum):
    ADMIN = "admin"
    PAGE_SERVER_API = "pageserverapi"
    GENERATIONS_API = "generations_api"
    SAFEKEEPER_DATA = "safekeeperdata"
    TENANT = "tenant"
    SCRUBBER = "scrubber"
    INFRA = "infra"
    # Read-only: `/metrics` on the pageserver, the safekeeper and the storage controller.
    METRICS = "metrics"
