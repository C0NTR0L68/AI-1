"""OFF-by-default explicit-choice candidate, NOT the active HYBRID router.

No settings, paths, keys or automatic routing. Only trusted future application
code may supply factories and provenance flags. Flags do not inspect messages
or authenticate their author. Production policy/cutover still needs approval.
"""
from enum import Enum
from typing import Callable

from app.provider import GenerationResult


class ExplicitPolicyDenied(PermissionError):
    """Fixed code only; no prompts, credentials or provider URLs."""


class ExecutionTarget(str, Enum):
    LOCAL = "LOCAL"
    CLOUD = "CLOUD"


class ExplicitHybridProvider:
    def __init__(self, *, enabled=False, cloud_allowed=False,
                 local_factory: Callable | None = None, cloud_factory: Callable | None = None):
        if type(enabled) is not bool or type(cloud_allowed) is not bool:
            raise ValueError("Explicit boolean configuration required")
        if enabled and (not callable(local_factory) or cloud_allowed and not callable(cloud_factory)):
            raise ValueError("Explicit selected-provider factories required")
        self._enabled = enabled
        self._cloud_allowed = cloud_allowed
        self._local_factory = local_factory
        self._cloud_factory = cloud_factory

    async def generate(self, messages, *, target="LOCAL", cloud_consent=False,
                       has_documents=False, document_consent=False, has_memory=False):
        if not self._enabled:
            raise ExplicitPolicyDenied("EXPLICIT_POLICY_DISABLED")
        if any(type(flag) is not bool for flag in (cloud_consent, has_documents, document_consent, has_memory)):
            raise ValueError("Explicit boolean permissions required")
        try:
            chosen = ExecutionTarget(target)
        except (ValueError, TypeError):
            raise ExplicitPolicyDenied("INVALID_EXECUTION_TARGET") from None
        if has_memory:
            raise ExplicitPolicyDenied("MEMORY_MODEL_USE_NOT_APPROVED")
        if chosen is ExecutionTarget.CLOUD:
            if not self._cloud_allowed or not cloud_consent:
                raise ExplicitPolicyDenied("CLOUD_CONSENT_REQUIRED")
            if has_documents:
                raise ExplicitPolicyDenied("CLOUD_DOCUMENT_USE_NOT_APPROVED")
            factory = self._cloud_factory
        else:
            if has_documents and not document_consent:
                raise ExplicitPolicyDenied("LOCAL_DOCUMENT_CONSENT_REQUIRED")
            factory = self._local_factory
        # Check all permissions before constructing any provider. No exception
        # handler performs fallback/retry; request dedup remains the store's job.
        provider = factory()
        result = await provider.generate(messages)
        if not isinstance(result, GenerationResult):
            raise TypeError("Invalid provider generation result")
        return result
