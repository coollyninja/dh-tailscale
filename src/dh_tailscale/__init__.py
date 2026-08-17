"""Read-only Tailscale integration for Deckhand."""

from .plugin import create_plugin

__all__ = ["create_plugin"]
