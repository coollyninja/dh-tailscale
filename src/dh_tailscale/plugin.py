from __future__ import annotations

import asyncio
import json
import re
import ssl
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from time import monotonic
from typing import Any

import httpx
from deckhand.adapters import (
    AdapterCancellation,
    AdapterError,
    AdapterErrorKind,
    AdapterExecution,
    AdapterHealth,
    AdapterHealthState,
    AdapterObservation,
    AdapterPlan,
    AdapterVerification,
    CancellationDisposition,
)
from deckhand.models import (
    ActionDefinition,
    ActionRequest,
    ConfirmationMode,
    RetryDisposition,
    RiskClass,
    StatusValue,
    StrictModel,
)
from deckhand.plugin_api import (
    DeckhandPlugin,
    PluginContext,
    PluginContribution,
    PluginManifest,
    PluginPermissions,
)
from pydantic import Field, field_validator, model_validator

API_ORIGIN = "https://api.tailscale.com"
OAUTH_PATH = "/api/v2/oauth/token"
DEVICES_PATH = "/api/v2/tailnet/-/devices"
OAUTH_SCOPE = "devices:core:read"
MAX_CREDENTIAL_BYTES = 4096
MAX_RESPONSE_BYTES = 2_097_152


class TailscaleCheckKind(StrEnum):
    FLEET = "fleet"
    STALE = "stale"
    KEY_EXPIRY = "key_expiry"


class TailscaleCheck(StrictModel):
    kind: TailscaleCheckKind
    maximum_offline: int | None = Field(default=None, ge=0, le=100_000)
    maximum_unauthorized: int | None = Field(default=None, ge=0, le=100_000)
    maximum_expired: int | None = Field(default=None, ge=0, le=100_000)
    maximum_age_seconds: int | None = Field(default=None, ge=60, le=31_536_000)
    maximum_stale: int | None = Field(default=None, ge=0, le=100_000)
    window_days: int | None = Field(default=None, ge=1, le=365)
    maximum_expiring: int | None = Field(default=None, ge=0, le=100_000)
    stale_after_seconds: int = Field(default=60, ge=1, le=3600)

    @model_validator(mode="after")
    def validate_shape(self) -> TailscaleCheck:
        fleet_fields = (
            self.maximum_offline,
            self.maximum_unauthorized,
            self.maximum_expired,
        )
        stale_fields = (self.maximum_age_seconds, self.maximum_stale)
        expiry_fields = (self.window_days, self.maximum_expiring)
        if self.kind == TailscaleCheckKind.FLEET:
            if any(value is None for value in fleet_fields):
                raise ValueError("fleet checks require all fleet thresholds")
            if any(value is not None for value in stale_fields + expiry_fields):
                raise ValueError("fleet checks do not accept stale or expiry thresholds")
        elif self.kind == TailscaleCheckKind.STALE:
            if any(value is None for value in stale_fields):
                raise ValueError("stale checks require maximum_age_seconds and maximum_stale")
            if any(value is not None for value in fleet_fields + expiry_fields):
                raise ValueError("stale checks do not accept fleet or expiry thresholds")
        else:
            if any(value is None for value in expiry_fields):
                raise ValueError("key_expiry checks require window_days and maximum_expiring")
            if any(value is not None for value in fleet_fields + stale_fields):
                raise ValueError("key_expiry checks do not accept fleet or stale thresholds")
        return self


class TailscaleConfig(StrictModel):
    oauth_client_id_file: Path
    oauth_client_secret_file: Path
    ca_file: Path | None = None
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    checks: dict[str, TailscaleCheck] = Field(min_length=1, max_length=128)

    @field_validator("oauth_client_id_file", "oauth_client_secret_file", "ca_file")
    @classmethod
    def validate_file_path(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("credential and CA file paths must be absolute")
        return value

    @field_validator("checks")
    @classmethod
    def validate_check_aliases(cls, value: dict[str, TailscaleCheck]) -> dict[str, TailscaleCheck]:
        if any(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", alias) is None for alias in value):
            raise ValueError("check aliases must be lowercase logical identifiers")
        return value


class TailscaleClient:
    def __init__(
        self,
        config: TailscaleConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self.config = config
        self.transport = transport
        self.wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self.monotonic_clock = monotonic_clock or monotonic
        self._token: str | None = None
        self._token_expires_at = 0.0
        self._token_lock = asyncio.Lock()

    @staticmethod
    def _credential(path: Path) -> str:
        try:
            if path.stat().st_size > MAX_CREDENTIAL_BYTES:
                raise AdapterError(
                    "credential file exceeds size limit",
                    kind=AdapterErrorKind.CONFIGURATION,
                )
            value = path.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise AdapterError(
                "credential file is unavailable",
                kind=AdapterErrorKind.CONFIGURATION,
            ) from error
        if not value:
            raise AdapterError("credential file is empty", kind=AdapterErrorKind.CONFIGURATION)
        return value

    def _verify(self) -> bool | ssl.SSLContext:
        if self.config.ca_file is None:
            return True
        try:
            return ssl.create_default_context(cafile=str(self.config.ca_file))
        except (OSError, ssl.SSLError) as error:
            raise AdapterError(
                "TLS CA file is unavailable or invalid",
                kind=AdapterErrorKind.CONFIGURATION,
            ) from error

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            async with (
                httpx.AsyncClient(
                    base_url=API_ORIGIN,
                    timeout=self.config.timeout_seconds,
                    verify=self._verify(),
                    follow_redirects=False,
                    trust_env=False,
                    transport=self.transport,
                ) as client,
                client.stream(
                    method,
                    path,
                    headers=headers,
                    data=data,
                ) as response,
            ):
                if response.is_redirect:
                    raise AdapterError(
                        "Tailscale redirect refused",
                        kind=AdapterErrorKind.PROTOCOL,
                    )
                self._raise_status(response.status_code)
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise AdapterError(
                            "Tailscale response exceeds size limit",
                            kind=AdapterErrorKind.PROTOCOL,
                        )
                    body.extend(chunk)
        except AdapterError:
            raise
        except httpx.TimeoutException as error:
            raise AdapterError(
                "Tailscale request timed out",
                kind=AdapterErrorKind.TIMEOUT,
                retry=RetryDisposition.SAFE,
            ) from error
        except httpx.HTTPError as error:
            raise AdapterError(
                "Tailscale is unavailable",
                kind=AdapterErrorKind.UNAVAILABLE,
                retry=RetryDisposition.SAFE,
            ) from error
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AdapterError(
                "Tailscale returned invalid JSON",
                kind=AdapterErrorKind.PROTOCOL,
            ) from error
        if not isinstance(payload, dict):
            raise AdapterError(
                "Tailscale returned an invalid response shape",
                kind=AdapterErrorKind.PROTOCOL,
            )
        return payload

    @staticmethod
    def _raise_status(status_code: int) -> None:
        if status_code == 401:
            raise AdapterError(
                "Tailscale authentication failed",
                kind=AdapterErrorKind.AUTHENTICATION,
            )
        if status_code == 403:
            raise AdapterError(
                "Tailscale authorization failed",
                kind=AdapterErrorKind.AUTHORIZATION,
            )
        if status_code == 404:
            raise AdapterError(
                "Tailscale API endpoint was not found",
                kind=AdapterErrorKind.NOT_FOUND,
            )
        if status_code == 429:
            raise AdapterError(
                "Tailscale rate limit reached",
                kind=AdapterErrorKind.RATE_LIMITED,
                retry=RetryDisposition.SAFE,
            )
        if status_code >= 500:
            raise AdapterError(
                "Tailscale returned a server error",
                kind=AdapterErrorKind.UNAVAILABLE,
                retry=RetryDisposition.SAFE,
            )
        if status_code < 200 or status_code >= 300:
            raise AdapterError(
                "Tailscale returned an unexpected status",
                kind=AdapterErrorKind.PROTOCOL,
            )

    async def _access_token(self) -> str:
        async with self._token_lock:
            now = self.monotonic_clock()
            if self._token is not None and now < self._token_expires_at:
                return self._token
            payload = await self._request_json(
                "POST",
                OAUTH_PATH,
                data={
                    "client_id": self._credential(self.config.oauth_client_id_file),
                    "client_secret": self._credential(self.config.oauth_client_secret_file),
                    "scope": OAUTH_SCOPE,
                },
            )
            token = payload.get("access_token")
            expires_in = payload.get("expires_in")
            if (
                not isinstance(token, str)
                or not token
                or len(token) > MAX_CREDENTIAL_BYTES
                or not isinstance(expires_in, int)
                or isinstance(expires_in, bool)
                or expires_in <= 0
                or expires_in > 86_400
            ):
                raise AdapterError(
                    "Tailscale returned an invalid OAuth response",
                    kind=AdapterErrorKind.PROTOCOL,
                )
            self._token = token
            self._token_expires_at = now + max(1, expires_in - 60)
            return token

    async def devices(self) -> list[dict[str, Any]]:
        token = await self._access_token()
        payload = await self._request_json(
            "GET",
            DEVICES_PATH,
            headers={"Authorization": f"Bearer {token}"},
        )
        raw_devices = payload.get("devices")
        if not isinstance(raw_devices, list) or len(raw_devices) > 100_000:
            raise AdapterError(
                "Tailscale returned an invalid device collection",
                kind=AdapterErrorKind.PROTOCOL,
            )
        if any(not isinstance(device, dict) for device in raw_devices):
            raise AdapterError(
                "Tailscale returned an invalid device record",
                kind=AdapterErrorKind.PROTOCOL,
            )
        return raw_devices

    async def health(self) -> AdapterHealth:
        devices = await self.devices()
        return AdapterHealth(
            state=AdapterHealthState.HEALTHY,
            details={"device_count": len(devices), "scope": OAUTH_SCOPE},
        )

    async def observe(self, check: TailscaleCheck) -> AdapterObservation:
        devices = await self.devices()
        if check.kind == TailscaleCheckKind.FLEET:
            return self._fleet(devices, check)
        if check.kind == TailscaleCheckKind.STALE:
            return self._stale(devices, check)
        return self._key_expiry(devices, check)

    def _fleet(self, devices: list[dict[str, Any]], check: TailscaleCheck) -> AdapterObservation:
        online = sum(device.get("online") is True for device in devices)
        offline = sum(device.get("online") is False for device in devices)
        unknown_online = len(devices) - online - offline
        unauthorized = sum(device.get("authorized") is False for device in devices)
        unknown_authorization = sum(
            not isinstance(device.get("authorized"), bool) for device in devices
        )
        expired = sum(self._is_expired(device) for device in devices)
        maximum_offline = self._required(check.maximum_offline)
        maximum_unauthorized = self._required(check.maximum_unauthorized)
        maximum_expired = self._required(check.maximum_expired)
        healthy = (
            offline <= maximum_offline
            and unauthorized <= maximum_unauthorized
            and expired <= maximum_expired
        )
        return AdapterObservation(
            state="healthy" if healthy else "degraded",
            details={
                "total_count": len(devices),
                "online_count": online,
                "offline_count": offline,
                "online_unknown_count": unknown_online,
                "unauthorized_count": unauthorized,
                "approval_unknown_count": unknown_authorization,
                "expired_count": expired,
                "maximum_offline": maximum_offline,
                "maximum_unauthorized": maximum_unauthorized,
                "maximum_expired": maximum_expired,
            },
        )

    def _stale(self, devices: list[dict[str, Any]], check: TailscaleCheck) -> AdapterObservation:
        maximum_age_seconds = self._required(check.maximum_age_seconds)
        maximum_stale = self._required(check.maximum_stale)
        cutoff = self.wall_clock() - timedelta(seconds=maximum_age_seconds)
        stale = 0
        never_seen = 0
        for device in devices:
            if device.get("online") is True:
                continue
            last_seen = self._timestamp(device.get("lastSeen"))
            if last_seen is None:
                never_seen += 1
            elif last_seen < cutoff:
                stale += 1
        count = stale + never_seen
        return AdapterObservation(
            state="healthy" if count <= maximum_stale else "degraded",
            details={
                "total_count": len(devices),
                "stale_count": stale,
                "never_seen_count": never_seen,
                "maximum_stale": maximum_stale,
                "maximum_age_seconds": maximum_age_seconds,
            },
        )

    def _key_expiry(
        self, devices: list[dict[str, Any]], check: TailscaleCheck
    ) -> AdapterObservation:
        window_days = self._required(check.window_days)
        maximum_expiring = self._required(check.maximum_expiring)
        now = self.wall_clock()
        cutoff = now + timedelta(days=window_days)
        expired = 0
        expiring = 0
        no_expiry = 0
        for device in devices:
            expires = self._timestamp(device.get("expires"))
            if self._is_expired(device, now=now, expires=expires):
                expired += 1
            elif expires is None:
                no_expiry += 1
            elif expires <= cutoff:
                expiring += 1
        unhealthy = expired + expiring
        return AdapterObservation(
            state="healthy" if unhealthy <= maximum_expiring else "degraded",
            details={
                "total_count": len(devices),
                "expiring_count": expiring,
                "expired_count": expired,
                "no_expiry_count": no_expiry,
                "window_days": window_days,
                "maximum_expiring": maximum_expiring,
            },
        )

    def _is_expired(
        self,
        device: Mapping[str, Any],
        *,
        now: datetime | None = None,
        expires: datetime | None = None,
    ) -> bool:
        if device.get("expired") is True:
            return True
        expiry = expires if expires is not None else self._timestamp(device.get("expires"))
        return expiry is not None and expiry <= (now or self.wall_clock())

    @staticmethod
    def _required(value: int | None) -> int:
        if value is None:
            raise AdapterError(
                "Tailscale check is missing a required threshold",
                kind=AdapterErrorKind.CONFIGURATION,
            )
        return value

    @staticmethod
    def _timestamp(value: Any) -> datetime | None:
        if value is None or value == "":
            return None
        if not isinstance(value, str) or len(value) > 64:
            raise AdapterError(
                "Tailscale returned an invalid timestamp",
                kind=AdapterErrorKind.PROTOCOL,
            )
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise AdapterError(
                "Tailscale returned an invalid timestamp",
                kind=AdapterErrorKind.PROTOCOL,
            ) from error
        if parsed.tzinfo is None:
            raise AdapterError(
                "Tailscale returned a timestamp without a timezone",
                kind=AdapterErrorKind.PROTOCOL,
            )
        return parsed.astimezone(UTC)


class TailscaleReadAdapter:
    def __init__(self, client: TailscaleClient, checks: Mapping[str, TailscaleCheck]) -> None:
        self.client = client
        self.checks = dict(checks)

    def _check(self, request: ActionRequest) -> TailscaleCheck:
        try:
            return self.checks[request.target.id]
        except KeyError as error:
            raise AdapterError(
                "Tailscale check alias is not configured",
                kind=AdapterErrorKind.NOT_FOUND,
            ) from error

    async def health(self) -> AdapterHealth:
        return await self.client.health()

    async def plan(self, action: ActionDefinition, request: ActionRequest) -> AdapterPlan:
        self._check(request)
        return AdapterPlan(
            steps=[
                "resolve configured check alias",
                "obtain scoped Tailscale access token",
                "read tailnet device summary",
                "verify minimized observation",
            ]
        )

    async def execute(self, action: ActionDefinition, request: ActionRequest) -> AdapterExecution:
        self._check(request)
        return AdapterExecution(reference=f"observe:{request.target.id}")

    async def observe(self, action: ActionDefinition, request: ActionRequest) -> AdapterObservation:
        return await self.client.observe(self._check(request))

    async def verify(
        self,
        action: ActionDefinition,
        request: ActionRequest,
        execution: AdapterExecution,
        observation: AdapterObservation,
    ) -> AdapterVerification:
        return AdapterVerification(
            satisfied=observation.state != "unknown",
            details={"execution_reference": execution.reference},
        )

    async def cancel(
        self,
        action: ActionDefinition,
        request: ActionRequest,
        execution: AdapterExecution | None,
    ) -> AdapterCancellation:
        return AdapterCancellation(disposition=CancellationDisposition.ALREADY_TERMINAL)


class TailscaleStatusProvider:
    def __init__(self, client: TailscaleClient, check: TailscaleCheck) -> None:
        self.client = client
        self.check = check

    async def observe(self) -> StatusValue:
        observation = await self.client.observe(self.check)
        return StatusValue(
            state=observation.state,
            observed_at=observation.observed_at,
            stale_after_seconds=self.check.stale_after_seconds,
            details=observation.details,
        )


OBSERVE_ACTION = ActionDefinition(
    id="tailscale.check.observe",
    version=1,
    title="Observe Tailscale check",
    description="Read a configured logical Tailscale fleet check alias.",
    risk_class=RiskClass.READ,
    plugin="dh-tailscale",
    adapter="dh-tailscale.read",
    target_types=["tailscale_check"],
    parameter_schema={
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {},
    },
    policy_action="tailscale.check.observe",
    confirmation=ConfirmationMode.NONE,
    timeout_seconds=30,
    idempotency="read-only",
    mutation=False,
)


CHECK_PROPERTIES: dict[str, Any] = {
    "kind": {"enum": [kind.value for kind in TailscaleCheckKind]},
    "maximum_offline": {"type": "integer", "minimum": 0, "maximum": 100000},
    "maximum_unauthorized": {"type": "integer", "minimum": 0, "maximum": 100000},
    "maximum_expired": {"type": "integer", "minimum": 0, "maximum": 100000},
    "maximum_age_seconds": {"type": "integer", "minimum": 60, "maximum": 31536000},
    "maximum_stale": {"type": "integer", "minimum": 0, "maximum": 100000},
    "window_days": {"type": "integer", "minimum": 1, "maximum": 365},
    "maximum_expiring": {"type": "integer", "minimum": 0, "maximum": 100000},
    "stale_after_seconds": {
        "type": "integer",
        "minimum": 1,
        "maximum": 3600,
        "default": 60,
    },
}

CONFIG_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["oauth_client_id_file", "oauth_client_secret_file", "checks"],
    "properties": {
        "oauth_client_id_file": {"type": "string", "pattern": "^/"},
        "oauth_client_secret_file": {"type": "string", "pattern": "^/"},
        "ca_file": {"type": ["string", "null"], "pattern": "^/"},
        "timeout_seconds": {
            "type": "number",
            "exclusiveMinimum": 0,
            "maximum": 30,
            "default": 5,
        },
        "checks": {
            "type": "object",
            "minProperties": 1,
            "maxProperties": 128,
            "propertyNames": {"pattern": "^[a-z][a-z0-9_]{0,63}$"},
            "additionalProperties": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind"],
                "properties": CHECK_PROPERTIES,
                "allOf": [
                    {
                        "if": {"properties": {"kind": {"const": "fleet"}}},
                        "then": {
                            "required": [
                                "maximum_offline",
                                "maximum_unauthorized",
                                "maximum_expired",
                            ],
                            "not": {
                                "anyOf": [
                                    {"required": ["maximum_age_seconds"]},
                                    {"required": ["maximum_stale"]},
                                    {"required": ["window_days"]},
                                    {"required": ["maximum_expiring"]},
                                ]
                            },
                        },
                    },
                    {
                        "if": {"properties": {"kind": {"const": "stale"}}},
                        "then": {
                            "required": ["maximum_age_seconds", "maximum_stale"],
                            "not": {
                                "anyOf": [
                                    {"required": ["maximum_offline"]},
                                    {"required": ["maximum_unauthorized"]},
                                    {"required": ["maximum_expired"]},
                                    {"required": ["window_days"]},
                                    {"required": ["maximum_expiring"]},
                                ]
                            },
                        },
                    },
                    {
                        "if": {"properties": {"kind": {"const": "key_expiry"}}},
                        "then": {
                            "required": ["window_days", "maximum_expiring"],
                            "not": {
                                "anyOf": [
                                    {"required": ["maximum_offline"]},
                                    {"required": ["maximum_unauthorized"]},
                                    {"required": ["maximum_expired"]},
                                    {"required": ["maximum_age_seconds"]},
                                    {"required": ["maximum_stale"]},
                                ]
                            },
                        },
                    },
                ],
            },
        },
    },
}


class TailscalePlugin:
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="dh-tailscale",
            name="Tailscale",
            version="0.1.0",
            description="Read-only fleet health observation through logical checks.",
            adapters=["dh-tailscale.read"],
            status_provider_types=["tailscale-check"],
            actions=[OBSERVE_ACTION.id],
            permissions=PluginPermissions(
                mutation=False,
                credential_slots=[
                    "tailscale.oauth_client_id",
                    "tailscale.oauth_client_secret",
                    "tailscale.tls_ca",
                ],
                egress_bindings=["tailscale_api"],
            ),
            config_schema=CONFIG_SCHEMA,
        )

    def build(self, context: PluginContext) -> PluginContribution:
        config = TailscaleConfig.model_validate(dict(context.config))
        client = TailscaleClient(config)
        return PluginContribution(
            adapters={"dh-tailscale.read": TailscaleReadAdapter(client, config.checks)},
            status_providers={
                alias: TailscaleStatusProvider(client, check)
                for alias, check in config.checks.items()
            },
            actions=(OBSERVE_ACTION,),
        )


def create_plugin() -> DeckhandPlugin:
    return TailscalePlugin()
