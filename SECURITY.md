# Security policy

Please report suspected vulnerabilities privately through GitHub's security-advisory feature. Do not open a public issue containing credentials, device data, Tailnet identity, internal topology, or exploit details.

## Deployment expectations

- Create a dedicated OAuth client with only the `devices:core:read` scope.
- Deliver the client ID and secret through restricted files or sidecar-specific systemd credentials.
- Keep TLS verification enabled; use `ca_file` only for an approved trust bundle.
- Restrict sidecar egress to the official Tailscale API destination.
- Keep actual thresholds, site policy, and isolation bindings in a private site overlay.
- Prefer Deckhand's signed sidecar runtime even though version 0.1.x is read-only.

The plugin fixes all upstream origins and paths, refuses redirects, bounds response and credential sizes, minimizes observations, and never includes upstream response bodies in errors. It implements no Tailnet mutation action.
