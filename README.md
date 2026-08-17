# dh-tailscale

`dh-tailscale` is a read-only Tailscale integration plugin for [Deckhand](https://github.com/coollyninja/deckhand). It converts the Tailscale device API into minimized fleet, stale-device, and key-expiry observations addressed only by operator-configured logical aliases.

The plugin uses the fixed official API origin and fixed paths for OAuth token exchange and device listing. It requests only the `devices:core:read` OAuth scope. Callers cannot submit URLs, tailnet names, device IDs, tags, query parameters, credentials, or API operations. Returned observations contain counts and configured thresholds—not hostnames, addresses, user identities, tags, device IDs, or upstream response bodies.

Tailscale documents OAuth clients as the ongoing client-credentials mechanism for scoped API access and documents `devices:core:read` as access to the read-only device-list/detail endpoints. See [OAuth clients](https://tailscale.com/docs/features/oauth-clients) and [trust credential scopes](https://tailscale.com/docs/reference/trust-credentials).

## Configuration

```yaml
schema_version: 1
plugins:
  dh-tailscale:
    enabled: true
    runtime:
      timeout_seconds: 8
      max_concurrency: 2
      requests_per_second: 2
      burst: 2
      failure_threshold: 3
      recovery_seconds: 30
    config:
      oauth_client_id_file: /run/secrets/deckhand/tailscale-client-id
      oauth_client_secret_file: /run/secrets/deckhand/tailscale-client-secret
      timeout_seconds: 5
      checks:
        fleet_health:
          kind: fleet
          maximum_offline: 0
          maximum_unauthorized: 0
          maximum_expired: 0
          stale_after_seconds: 60
        stale_devices:
          kind: stale
          maximum_age_seconds: 86400
          maximum_stale: 0
          stale_after_seconds: 300
        key_expiry:
          kind: key_expiry
          window_days: 14
          maximum_expiring: 0
          stale_after_seconds: 3600
```

These are public shapes only. Actual thresholds, credentials, sidecar bindings, and policy belong in a private `deckhand-site-<site>` overlay.

## Verify

```bash
uv sync --locked --all-groups
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run python scripts/check_public_surface.py
uv run pytest
```

The plugin is MIT licensed.
