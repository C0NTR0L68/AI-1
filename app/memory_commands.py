"""Explicit Russian memory command intents, disabled unless opted in.

No persistence, authorization or model calls. An intent is not a saved fact and
must be confirmed through the future protected V2 operation/receipt boundary.
"""
from dataclasses import dataclass
from enum import Enum
import re
from uuid import UUID


class MemoryAction(str, Enum):
    SAVE = "save"
    LIST = "list"
    DELETE = "delete"


@dataclass(frozen=True)
class MemoryIntent:
    action: MemoryAction
    text: str | None = None
    note_id: str | None = None
    requires_confirmation: bool = True


_ADDRESS = re.compile(r"^ai-1\s*,\s*", re.IGNORECASE)
_SAVE = re.compile(r"^запомни(?:\s*,\s*что\s+|\s+что\s+|\s*:\s*)(.+)$", re.IGNORECASE | re.DOTALL)
_READ = re.compile(r"(?:что ты помнишь(?: обо мне)?|покажи память)[?.!]?\Z", re.IGNORECASE)
_DELETE = re.compile(r"^удали\s+из\s+памяти\s+([0-9a-f-]{36})$", re.IGNORECASE)


def parse_memory_command(message: str, *, enabled: bool = False) -> MemoryIntent | None:
    """Recognize only whole, owner-written explicit commands.

    Unrecognized ordinary chat is never converted into an instruction to store
    personal facts. Callers must not feed model responses/document excerpts into
    this parser. Enabling parsing does not enable Memory API or grant access.
    """
    if enabled is not True:
        return None
    if type(message) is not str or not message.strip() or "\x00" in message or len(message) > 12000:
        raise ValueError("Invalid memory command input")
    message.encode("utf-8", errors="strict")
    command = _ADDRESS.sub("", message.strip(), count=1)
    if _READ.fullmatch(command):
        return MemoryIntent(MemoryAction.LIST, requires_confirmation=False)
    match = _SAVE.fullmatch(command)
    if match:
        text = match.group(1).strip()
        # A parser transport bound, not the unapproved V2 storage quota/retention.
        if not text or len(text) > 2000 or len(text.encode("utf-8")) > 8000:
            raise ValueError("Memory command payload exceeds transport limit")
        return MemoryIntent(MemoryAction.SAVE, text=text)
    match = _DELETE.fullmatch(command)
    if match:
        note_id = str(UUID(match.group(1)))
        return MemoryIntent(MemoryAction.DELETE, note_id=note_id)
    return None
