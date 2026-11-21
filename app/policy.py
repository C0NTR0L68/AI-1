"""Explicit server policies; no policy performs automatic fallback or retries."""
from enum import Enum
from typing import Callable

from app.provider import ChatProvider
from app.router import ModelRouter


class ModelMode(str, Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    HYBRID = "HYBRID"
    LOCAL_ONLY = "LOCAL_ONLY"


_DEFAULT_MODES = {
    "gemini": ModelMode.ONLINE,
    "ollama": ModelMode.OFFLINE,
    "hybrid": ModelMode.HYBRID,
}
_ALLOWED_MODES = {
    "gemini": {ModelMode.ONLINE},
    "ollama": {ModelMode.OFFLINE, ModelMode.LOCAL_ONLY},
    "hybrid": {ModelMode.HYBRID},
}


def resolve_mode(provider: str, mode: str | None = None) -> ModelMode:
    """AI1_MODE refines AI1_PROVIDER; it never overrides a conflicting provider."""
    if not isinstance(provider, str) or provider.strip().lower() not in _DEFAULT_MODES:
        raise ValueError("AI1_PROVIDER must be 'gemini', 'ollama' or 'hybrid'")
    provider = provider.strip().lower()
    if mode is None or (isinstance(mode, str) and not mode.strip()):
        return _DEFAULT_MODES[provider]
    if not isinstance(mode, str):
        raise ValueError("AI1_MODE must be ONLINE, OFFLINE, HYBRID or LOCAL_ONLY")
    try:
        selected = ModelMode(mode.strip().upper())
    except ValueError:
        raise ValueError("AI1_MODE must be ONLINE, OFFLINE, HYBRID or LOCAL_ONLY") from None
    if selected not in _ALLOWED_MODES[provider]:
        raise ValueError("AI1_MODE conflicts with AI1_PROVIDER; choose a compatible pair")
    return selected


def build_policy_provider(
    mode: ModelMode,
    *,
    cloud_factory: Callable[[], ChatProvider] | None = None,
    local_factory: Callable[[], ChatProvider] | None = None,
) -> ChatProvider:
    """Only hand the selected policy the adapter factories it is allowed to use."""
    if not isinstance(mode, ModelMode):
        raise ValueError("Provider policy requires a resolved ModelMode")
    if mode in (ModelMode.OFFLINE, ModelMode.LOCAL_ONLY):
        if cloud_factory is not None:
            raise ValueError("Local policies cannot receive a cloud adapter factory")
        if not callable(local_factory):
            raise ValueError("Local policy requires a local adapter factory")
        return local_factory()
    if mode is ModelMode.ONLINE:
        if local_factory is not None:
            raise ValueError("ONLINE policy cannot receive a fallback adapter factory")
        if not callable(cloud_factory):
            raise ValueError("ONLINE policy requires a cloud adapter factory")
        return cloud_factory()
    if not callable(cloud_factory) or not callable(local_factory):
        raise ValueError("HYBRID policy requires cloud and local adapter factories")
    return ModelRouter(cloud_factory, local_factory, primary="cloud")
