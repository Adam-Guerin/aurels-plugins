from .plugin import AurelsHermesPlugin


def register(ctx):
    plugin = AurelsHermesPlugin()
    plugin.register(ctx)
    return plugin


__all__ = ["AurelsHermesPlugin", "register"]
