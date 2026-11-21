from dataclasses import dataclass
from enum import Enum
from typing import Protocol

import httpx


class ProviderErrorCategory(str, Enum):
    TRANSIENT_NETWORK = "transient_network"
    TRANSIENT_SERVICE = "transient_service"
    AUTHENTICATION = "authentication"
    CONFIGURATION = "configuration"
    INVALID_REQUEST = "invalid_request"
    UNKNOWN = "unknown"


class ProviderAttemptOutcome(str, Enum):
    NOT_SENT = "not_sent"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class ProviderError(RuntimeError):
    """Provider failure with a stable category for later routing decisions."""

    def __init__(
        self,
        category: ProviderErrorCategory,
        message: str,
        *,
        provider_id: str,
        status_code: int | None = None,
        provider_code: str | None = None,
        attempt_outcome: ProviderAttemptOutcome = ProviderAttemptOutcome.UNKNOWN,
    ):
        super().__init__(message)
        self.category = category
        self.provider_id = provider_id
        self.status_code = status_code
        self.provider_code = provider_code
        self.attempt_outcome = ProviderAttemptOutcome(attempt_outcome)


def _error_details(response: httpx.Response) -> tuple[str, str | None]:
    detail = "Provider rejected the request"
    provider_code = None
    try:
        error = response.json().get("error", {})
        if isinstance(error, dict):
            detail = error.get("message", detail)
            provider_code = error.get("code") or error.get("type")
        elif isinstance(error, str):
            detail = error
    except (ValueError, AttributeError, TypeError):
        pass
    return str(detail), str(provider_code) if provider_code is not None else None


def _classify_http_error(
    status_code: int,
    detail: str,
    provider_code: str | None,
    retry_after: str | None = None,
) -> ProviderErrorCategory:
    if status_code in (401, 403):
        return ProviderErrorCategory.AUTHENTICATION
    if status_code == 429:
        normalized_code = str(provider_code or "").strip().lower().replace("-", "_")
        normalized_detail = detail.lower()
        quota_markers = (
            "insufficient_quota",
            "quota_exceeded",
            "billing",
            "payment required",
            "credits exhausted",
        )
        rate_limit_codes = {"rate_limit", "rate_limit_exceeded", "too_many_requests"}
        has_quota_signal = any(
            marker in normalized_code or marker in normalized_detail
            for marker in quota_markers
        ) or "quota" in normalized_detail or "billing" in normalized_detail
        has_temporary_limit_signal = (
            normalized_code in rate_limit_codes
            or "rate limit" in normalized_detail
            or "too many requests" in normalized_detail
            or retry_after is not None
        )
        if has_quota_signal:
            return ProviderErrorCategory.CONFIGURATION
        if has_temporary_limit_signal:
            return ProviderErrorCategory.TRANSIENT_SERVICE
        return ProviderErrorCategory.UNKNOWN
    if status_code in (408, 425) or status_code >= 500:
        return ProviderErrorCategory.TRANSIENT_SERVICE
    if status_code in (400, 422):
        return ProviderErrorCategory.INVALID_REQUEST
    return ProviderErrorCategory.UNKNOWN


def _classify_http_attempt_outcome(
    status_code: int, detail: str, provider_code: str | None
) -> ProviderAttemptOutcome:
    # HTTP status and body alone do not prove the response came from the provider.
    return ProviderAttemptOutcome.UNKNOWN


def _classify_transport_attempt_outcome(
    error: httpx.TransportError,
) -> ProviderAttemptOutcome:
    if isinstance(
        error,
        (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.PoolTimeout,
        ),
    ):
        return ProviderAttemptOutcome.NOT_SENT
    return ProviderAttemptOutcome.UNKNOWN


@dataclass(frozen=True)
class GenerationResult:
    text: str
    provider_id: str
    requested_model: str
    provider_model: str | None = None

    @property
    def model_name(self) -> str:
        """Deprecated compatibility alias for the requested model."""
        return self.requested_model


class ChatProvider(Protocol):
    async def generate(self, messages: list[dict[str, str]]) -> GenerationResult: ...


class CloudProvider:
    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        timeout: float = 45.0,
        api_key_required: bool = True,
        provider_id: str = "openai_compatible",
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.api_key_required = api_key_required
        self.provider_id = provider_id

    async def generate(self, messages: list[dict[str, str]]) -> GenerationResult:
        if self.api_key_required and not self.api_key:
            raise ProviderError(
                ProviderErrorCategory.CONFIGURATION,
                "API key is not configured for the cloud provider",
                provider_id=self.provider_id,
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            )

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
        except (httpx.InvalidURL, httpx.UnsupportedProtocol) as exc:
            raise ProviderError(
                ProviderErrorCategory.CONFIGURATION,
                "Provider URL configuration is invalid",
                provider_id=self.provider_id,
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            ) from exc
        except httpx.TransportError as exc:
            raise ProviderError(
                ProviderErrorCategory.TRANSIENT_NETWORK,
                f"Provider network request failed ({type(exc).__name__})",
                provider_id=self.provider_id,
                attempt_outcome=_classify_transport_attempt_outcome(exc),
            ) from exc
        except Exception as exc:
            raise ProviderError(
                ProviderErrorCategory.UNKNOWN,
                f"Provider request failed ({type(exc).__name__})",
                provider_id=self.provider_id,
            ) from exc

        if response.status_code < 200 or 300 <= response.status_code < 400:
            # A redirect/informational body is not a confirmed generation result.
            # Do not follow it, parse its content or infer a provider rejection.
            raise ProviderError(
                ProviderErrorCategory.UNKNOWN,
                f"Provider returned a non-success response ({response.status_code})",
                provider_id=self.provider_id,
                status_code=response.status_code,
                attempt_outcome=ProviderAttemptOutcome.UNKNOWN,
            )

        if response.status_code >= 400:
            detail, provider_code = _error_details(response)
            category = _classify_http_error(
                response.status_code,
                detail,
                provider_code,
                response.headers.get("Retry-After"),
            )

            raise ProviderError(
                category,
                f"Provider error ({response.status_code}): {str(detail)[:400]}",
                provider_id=self.provider_id,
                status_code=response.status_code,
                provider_code=provider_code,
                attempt_outcome=_classify_http_attempt_outcome(
                    response.status_code, detail, provider_code
                ),
            )

        try:
            data = response.json()
            answer = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise ProviderError(
                ProviderErrorCategory.UNKNOWN,
                "Provider returned an unexpected response format",
                provider_id=self.provider_id,
                status_code=response.status_code,
            ) from None

        if not isinstance(answer, str) or not answer.strip():
            raise ProviderError(
                ProviderErrorCategory.UNKNOWN,
                "Provider returned an empty response",
                provider_id=self.provider_id,
                status_code=response.status_code,
            )

        return GenerationResult(
            text=answer.strip(),
            provider_id=self.provider_id,
            requested_model=self.model,
            provider_model=(
                data.get("model").strip()
                if isinstance(data.get("model"), str) and data["model"].strip()
                else None
            ),
        )

    async def reply(self, messages: list[dict[str, str]]) -> str:
        """Legacy string-returning API retained for existing callers."""
        return (await self.generate(messages)).text


# Backwards-compatible import name used by the current app and tests.
OpenAICompatibleProvider = CloudProvider
