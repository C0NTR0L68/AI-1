"""Explicit storage composition for a trusted, separately deployed authority."""
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, ContextManager
from uuid import UUID

from app.memory_head_v2 import AuthorityArchiveBackend, HeadUnavailable
from app.memory_image_ledger import MemoryImageLedger
from app.memory_windows_archive import PrivateArchiveDirectory


@dataclass(frozen=True, slots=True)
class MemoryStorageFactory:
    """Trusted launcher input. An authority session has no client-side DB path.

    The deployment must authenticate the authority and own its connection
    factory. Callers must supply the independently enrolled archive namespace.
    This factory neither provisions storage nor installs memory routes.
    """

    authority_session: Callable[[], ContextManager] = field(repr=False)
    archives: PrivateArchiveDirectory = field(repr=False)
    generation: UUID
    receipt_budget: int

    def __post_init__(self):
        if (not callable(self.authority_session) or type(self.archives) is not PrivateArchiveDirectory
                or type(self.generation) is not UUID or self.generation.int == 0
                or type(self.receipt_budget) is not int or not 1 <= self.receipt_budget <= 2**63 - 1):
            raise ValueError("Explicit trusted memory deployment required")

    @contextmanager
    def open(self):
        with self.authority_session() as authority:
            backend = AuthorityArchiveBackend(
                authority, generation=self.generation,
                read_archive=self.archives.read, publish_archive=self.archives.publish,
            )
            head = backend.head()
            with backend.open_image(head):
                pass
            if backend.head() != head:
                raise HeadUnavailable("head_changed_during_startup")
            yield MemoryImageLedger(backend, receipt_budget=self.receipt_budget)
