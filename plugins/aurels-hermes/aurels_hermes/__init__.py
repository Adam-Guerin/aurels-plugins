from .plugin import AurelsHermesPlugin, AurelsToolBlockedError


def register(ctx):
    plugin = AurelsHermesPlugin()
    plugin.register(ctx)
    return plugin


__all__ = ["AurelsHermesPlugin", "AurelsToolBlockedError", "register"]
