from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs
from uuid import UUID

import httpx
import pytest
import yaml
from deckhand.adapters import AdapterError, AdapterErrorKind, CancellationDisposition
from deckhand.models import ActionRequest, RequestContext, Target
from deckhand.plugins import (
    PluginActivation,
    PluginConfiguration,
    PluginLock,
    PluginLockEntry,
    PluginManager,
)

from dh_tailscale.plugin import (
    API_ORIGIN,
    DEVICES_PATH,
    OAUTH_PATH,
    OAUTH_SCOPE,
    OBSERVE_ACTION,
    TailscaleCheck,
    TailscaleClient,
    TailscaleConfig,
    TailscaleReadAdapter,
    create_plugin,
)

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def write_credential(path: Path, value: str) -> Path:
    path.write_text(value, encoding="utf-8")
    return path


def config(tmp_path: Path, *, checks: dict[str, dict[str, object]]) -> TailscaleConfig:
    return TailscaleConfig.model_validate(
        {
            "oauth_client_id_file": write_credential(tmp_path / "client-id", "client-id"),
            "oauth_client_secret_file": write_credential(tmp_path / "client-secret", "test-secret"),
            "checks": checks,
        }
    )


def request(alias: str) -> ActionRequest:
    return ActionRequest(
        action_id=OBSERVE_ACTION.id,
        action_version=1,
        target=Target(type="tailscale_check", id=alias),
        parameters={},
        context=RequestContext(client="test"),
        idempotency_key=UUID("00000000-0000-4000-8000-000000000001"),
    )


def token_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "access_token": "ephemeral-test-access-value",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": OAUTH_SCOPE,
        },
    )


def sample_devices() -> list[dict[str, object]]:
    return [
        {
            "id": "device-one",
            "hostname": "private-device-one",
            "addresses": ["redacted-address"],
            "online": True,
            "authorized": True,
            "lastSeen": "2026-08-16T11:59:00Z",
            "expires": "2026-08-25T12:00:00Z",
        },
        {
            "id": "device-two",
            "hostname": "private-device-two",
            "user": "operator@example.invalid",
            "online": False,
            "authorized": False,
            "expired": True,
            "lastSeen": "2026-07-01T00:00:00Z",
            "expires": "2026-08-15T12:00:00Z",
        },
        {
            "id": "device-three",
            "hostname": "private-device-three",
        },
    ]


def client(
    tmp_path: Path,
    checks: dict[str, dict[str, object]],
    handler: httpx.MockTransport,
) -> TailscaleClient:
    return TailscaleClient(
        config(tmp_path, checks=checks),
        transport=handler,
        wall_clock=lambda: NOW,
        monotonic_clock=lambda: 100.0,
    )


def device_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == OAUTH_PATH:
        assert request.method == "POST"
        form = parse_qs(request.content.decode("utf-8"))
        assert form == {
            "client_id": ["client-id"],
            "client_secret": ["test-secret"],
            "scope": [OAUTH_SCOPE],
        }
        return token_response()
    assert request.method == "GET"
    assert request.url == f"{API_ORIGIN}{DEVICES_PATH}"
    assert request.headers["Authorization"] == "Bearer ephemeral-test-access-value"
    return httpx.Response(200, json={"devices": sample_devices()})


def test_manifest_is_read_only_fixed_origin_and_matches_repository() -> None:
    manifest = create_plugin().manifest
    assert manifest.id == "dh-tailscale"
    assert manifest.api_version == 1
    assert manifest.permissions.mutation is False
    assert manifest.permissions.egress_bindings == ["tailscale_api"]
    assert OBSERVE_ACTION.mutation is False
    assert "endpoint" not in manifest.config_schema["properties"]
    with open("deckhand-plugin.yaml", encoding="utf-8") as manifest_file:
        assert yaml.safe_load(manifest_file) == manifest.model_dump(mode="json")


@pytest.mark.parametrize(
    "check",
    [
        {"kind": "fleet", "maximum_offline": 0, "maximum_unauthorized": 0},
        {
            "kind": "fleet",
            "maximum_offline": 0,
            "maximum_unauthorized": 0,
            "maximum_expired": 0,
            "window_days": 1,
        },
        {"kind": "stale", "maximum_age_seconds": 3600},
        {"kind": "key_expiry", "window_days": 14},
    ],
)
def test_check_rejects_mixed_or_incomplete_shapes(check: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        TailscaleCheck.model_validate(check)


def test_config_requires_absolute_credential_paths() -> None:
    with pytest.raises(ValueError, match="absolute"):
        TailscaleConfig.model_validate(
            {
                "oauth_client_id_file": "relative-id",
                "oauth_client_secret_file": "/absolute-secret",
                "checks": {
                    "fleet": {
                        "kind": "fleet",
                        "maximum_offline": 0,
                        "maximum_unauthorized": 0,
                        "maximum_expired": 0,
                    }
                },
            }
        )


@pytest.mark.asyncio
async def test_fleet_observation_uses_scoped_oauth_and_minimizes_output(tmp_path: Path) -> None:
    tailscale = client(
        tmp_path,
        {
            "fleet": {
                "kind": "fleet",
                "maximum_offline": 1,
                "maximum_unauthorized": 0,
                "maximum_expired": 0,
            }
        },
        httpx.MockTransport(device_handler),
    )
    check = TailscaleCheck.model_validate(
        {
            "kind": "fleet",
            "maximum_offline": 1,
            "maximum_unauthorized": 0,
            "maximum_expired": 0,
        }
    )
    observation = await tailscale.observe(check)
    assert observation.state == "degraded"
    assert observation.details == {
        "total_count": 3,
        "online_count": 1,
        "offline_count": 1,
        "online_unknown_count": 1,
        "unauthorized_count": 1,
        "approval_unknown_count": 1,
        "expired_count": 1,
        "maximum_offline": 1,
        "maximum_unauthorized": 0,
        "maximum_expired": 0,
    }
    rendered = str(observation.details)
    assert "device-one" not in rendered
    assert "private-device" not in rendered
    assert "redacted-address" not in rendered
    assert "operator" not in rendered


@pytest.mark.asyncio
async def test_stale_observation_skips_online_devices_and_counts_unknown(tmp_path: Path) -> None:
    tailscale = client(
        tmp_path,
        {"stale": {"kind": "stale", "maximum_age_seconds": 3600, "maximum_stale": 1}},
        httpx.MockTransport(device_handler),
    )
    observation = await tailscale.observe(
        TailscaleCheck.model_validate(
            {"kind": "stale", "maximum_age_seconds": 3600, "maximum_stale": 1}
        )
    )
    assert observation.state == "degraded"
    assert observation.details == {
        "total_count": 3,
        "stale_count": 1,
        "never_seen_count": 1,
        "maximum_stale": 1,
        "maximum_age_seconds": 3600,
    }


@pytest.mark.asyncio
async def test_key_expiry_observation_counts_without_returning_devices(tmp_path: Path) -> None:
    tailscale = client(
        tmp_path,
        {"keys": {"kind": "key_expiry", "window_days": 14, "maximum_expiring": 0}},
        httpx.MockTransport(device_handler),
    )
    observation = await tailscale.observe(
        TailscaleCheck.model_validate(
            {"kind": "key_expiry", "window_days": 14, "maximum_expiring": 0}
        )
    )
    assert observation.state == "degraded"
    assert observation.details == {
        "total_count": 3,
        "expiring_count": 1,
        "expired_count": 1,
        "no_expiry_count": 1,
        "window_days": 14,
        "maximum_expiring": 0,
    }


@pytest.mark.asyncio
async def test_oauth_token_is_cached_until_refresh_window(tmp_path: Path) -> None:
    token_requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_requests
        if request.url.path == OAUTH_PATH:
            token_requests += 1
            return token_response()
        return httpx.Response(200, json={"devices": []})

    tailscale = client(
        tmp_path,
        {
            "fleet": {
                "kind": "fleet",
                "maximum_offline": 0,
                "maximum_unauthorized": 0,
                "maximum_expired": 0,
            }
        },
        httpx.MockTransport(handler),
    )
    await tailscale.devices()
    await tailscale.devices()
    assert token_requests == 1


@pytest.mark.asyncio
async def test_redirect_and_upstream_body_are_not_exposed(tmp_path: Path) -> None:
    redirecting = client(
        tmp_path,
        {
            "fleet": {
                "kind": "fleet",
                "maximum_offline": 0,
                "maximum_unauthorized": 0,
                "maximum_expired": 0,
            }
        },
        httpx.MockTransport(
            lambda _: httpx.Response(302, headers={"location": "https://other.example.invalid"})
        ),
    )
    with pytest.raises(AdapterError) as redirect:
        await redirecting.health()
    assert redirect.value.kind == AdapterErrorKind.PROTOCOL

    unauthorized = client(
        tmp_path,
        {
            "fleet": {
                "kind": "fleet",
                "maximum_offline": 0,
                "maximum_unauthorized": 0,
                "maximum_expired": 0,
            }
        },
        httpx.MockTransport(
            lambda _: httpx.Response(401, text="diagnostic containing test-secret")
        ),
    )
    with pytest.raises(AdapterError) as captured:
        await unauthorized.health()
    assert captured.value.kind == AdapterErrorKind.AUTHENTICATION
    assert "test-secret" not in str(captured.value)
    assert "diagnostic" not in str(captured.value)


@pytest.mark.asyncio
async def test_invalid_timestamp_is_a_typed_protocol_failure(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == OAUTH_PATH:
            return token_response()
        return httpx.Response(200, json={"devices": [{"lastSeen": "not-a-time"}]})

    tailscale = client(
        tmp_path,
        {"stale": {"kind": "stale", "maximum_age_seconds": 3600, "maximum_stale": 0}},
        httpx.MockTransport(handler),
    )
    with pytest.raises(AdapterError) as captured:
        await tailscale.observe(
            TailscaleCheck.model_validate(
                {"kind": "stale", "maximum_age_seconds": 3600, "maximum_stale": 0}
            )
        )
    assert captured.value.kind == AdapterErrorKind.PROTOCOL


@pytest.mark.asyncio
async def test_adapter_implements_full_read_only_lifecycle(tmp_path: Path) -> None:
    tailscale_config = config(
        tmp_path,
        checks={
            "fleet": {
                "kind": "fleet",
                "maximum_offline": 1,
                "maximum_unauthorized": 1,
                "maximum_expired": 1,
            }
        },
    )
    tailscale = TailscaleClient(
        tailscale_config,
        transport=httpx.MockTransport(device_handler),
        wall_clock=lambda: NOW,
        monotonic_clock=lambda: 100.0,
    )
    adapter = TailscaleReadAdapter(tailscale, tailscale_config.checks)
    action_request = request("fleet")
    plan = await adapter.plan(OBSERVE_ACTION, action_request)
    execution = await adapter.execute(OBSERVE_ACTION, action_request)
    observation = await adapter.observe(OBSERVE_ACTION, action_request)
    verification = await adapter.verify(OBSERVE_ACTION, action_request, execution, observation)
    cancellation = await adapter.cancel(OBSERVE_ACTION, action_request, execution)

    assert len(plan.steps) == 4
    assert execution.reference == "observe:fleet"
    assert observation.state == "healthy"
    assert verification.satisfied is True
    assert cancellation.disposition == CancellationDisposition.ALREADY_TERMINAL


def test_core_discovers_loads_and_wraps_installed_plugin(tmp_path: Path) -> None:
    plugin_config = config(
        tmp_path,
        checks={
            "fleet": {
                "kind": "fleet",
                "maximum_offline": 0,
                "maximum_unauthorized": 0,
                "maximum_expired": 0,
            }
        },
    )
    loaded = PluginManager().load(
        PluginConfiguration(
            plugins={
                "dh-core": PluginActivation(),
                "dh-tailscale": PluginActivation(
                    config=plugin_config.model_dump(mode="json", exclude_none=True)
                ),
            }
        ),
        PluginLock(
            plugins=[
                PluginLockEntry(id="dh-core", version="0.5.0", source="builtin"),
                PluginLockEntry(id="dh-tailscale", version="0.1.0", source="python"),
            ]
        ),
        allow_external=True,
    )
    assert [manifest.id for manifest in loaded.manifests] == ["dh-core", "dh-tailscale"]
    assert loaded.adapters.get("dh-tailscale.read")
    assert set(loaded.status.providers) == {"fleet"}
    assert set(loaded.resilience) == {"dh-core", "dh-tailscale"}
