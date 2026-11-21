"""Server-side routing foundation. Automatic fallback and retries are disabled."""
import logging
from threading import Lock
from time import perf_counter
from typing import Callable, Literal

from app.provider import ChatProvider, GenerationResult, ProviderError

logger = logging.getLogger(__name__)


class ModelRouter:
    """Select one fixed primary adapter; leave request ownership to the API/store."""

    def __init__(
        self,
        cloud_factory: Callable[[], ChatProvider],
        local_factory: Callable[[], ChatProvider],
        *,
        primary: Literal["cloud", "local"] = "cloud",
    ):
        if primary not in ("cloud", "local"):
            raise ValueError("Router primary must be 'cloud' or 'local'")
        self._primary = primary
        self._factories = {"cloud": cloud_factory, "local": local_factory}
        self._provider: ChatProvider | None = None
        self._factory_lock = Lock()

    @property
    def primary(self) -> str:
        return self._primary

    def selected_provider(self) -> ChatProvider:
        # Factories only construct adapters; availability is determined by generate().
        with self._factory_lock:
            if self._provider is None:
                self._provider = self._factories[self._primary]()
            return self._provider

    async def generate(self, messages: list[dict[str, str]]) -> GenerationResult:
        started = perf_counter()
        logger.info("Model route selected primary=%s fallback=disabled", self._primary)
        try:
            result = await self.selected_provider().generate(messages)
            if not isinstance(result, GenerationResult):
                raise TypeError("Routed provider returned an invalid generation result")
        except ProviderError as error:
            logger.warning(
                "Model route failed primary=%s category=%s outcome=%s elapsed_ms=%.1f",
                self._primary, error.category.value, error.attempt_outcome.value,
                (perf_counter() - started) * 1000,
            )
            raise
        except Exception as error:
            logger.error(
                "Model route failed primary=%s error_type=%s elapsed_ms=%.1f",
                self._primary, type(error).__name__, (perf_counter() - started) * 1000,
            )
            raise
        logger.info(
            "Model route completed primary=%s provider=%s elapsed_ms=%.1f",
            self._primary, result.provider_id, (perf_counter() - started) * 1000,
        )
        return result

    async def reply(self, messages: list[dict[str, str]]) -> str:
        return (await self.generate(messages)).text
