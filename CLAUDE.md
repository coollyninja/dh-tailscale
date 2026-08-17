# dh-tailscale agent context

Read `../CLAUDE.md` before changing this repository.

This is a public, read-only Deckhand plugin. Preserve the fixed official Tailscale API origin and paths, OAuth `devices:core:read` scope, file-backed credentials, TLS verification, redirect refusal, response bounds, minimized count-only output, typed sanitized errors, and full adapter lifecycle. Clients must never submit URLs, Tailnet names, device identities, tags, API operations, query parameters, or credentials. Do not add real endpoints, device data, secrets, thresholds derived from a private site, or site policy.

Run Ruff, Ruff format check, strict mypy, pytest, and the public-surface scanner before publishing.
