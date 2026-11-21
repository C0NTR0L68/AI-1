import ipaddress
import json
from urllib.parse import urlsplit

import httpx

from app.provider import (
    GenerationResult,
    ProviderAttemptOutcome,
    ProviderError,
    ProviderErrorCategory,
    _classify_http_error,
    _classify_http_attempt_outcome,
    _classify_transport_attempt_outcome,
    _error_details,
)


class OllamaProvider:
    """Local-only adapter for Ollama's native HTTP API."""

    _DOCUMENT_OUTPUT_TOKENS = 256
    _DOCUMENT_TEMPERATURE = 0.0
    _UNCONFIRMED_DOCUMENT_ANSWER = "Не удалось подтвердить ответ по выбранным фрагментам."
    _LOOPBACK_ADDRESSES = {
        ipaddress.IPv4Address("127.0.0.1"),
        ipaddress.IPv6Address("::1"),
    }

    def __init__(
        self,
        model: str,
        base_url: str = "http://127.0.0.1:11434",
        timeout: float = 45.0,
        num_gpu: int = 0,
    ):
        self.provider_id = "ollama"
        self.model = model.strip()
        self.timeout = timeout
        if isinstance(num_gpu, bool) or not isinstance(num_gpu, int) or num_gpu < 0:
            raise ProviderError(
                ProviderErrorCategory.CONFIGURATION,
                "Ollama num_gpu must be a non-negative integer",
                provider_id=self.provider_id,
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            )
        self.num_gpu = num_gpu
        self.base_url = self._validated_base_url(base_url)

    @classmethod
    def _validated_base_url(cls, base_url: str) -> str:
        try:
            parsed = urlsplit(base_url)
            hostname = parsed.hostname
            port = parsed.port  # Force malformed/out-of-range port values to fail.
        except (AttributeError, ValueError) as exc:
            raise ProviderError(
                ProviderErrorCategory.CONFIGURATION,
                "Ollama URL configuration is invalid",
                provider_id="ollama",
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            ) from exc

        try:
            address = ipaddress.ip_address(hostname) if hostname is not None else None
        except ValueError:
            address = None

        explicit_empty_port = parsed.netloc.endswith(":")
        if (
            parsed.scheme != "http"
            or address not in cls._LOOPBACK_ADDRESSES
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path.rstrip("/") not in ("", "/v1")
            or explicit_empty_port
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ProviderError(
                ProviderErrorCategory.CONFIGURATION,
                "Ollama URL must use HTTP and the literal loopback IP 127.0.0.1 or ::1",
                provider_id="ollama",
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            )

        return f"http://{parsed.netloc}"

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, trust_env=False, follow_redirects=False
            ) as client:
                response = await client.request(method, f"{self.base_url}{path}", **kwargs)
        except (httpx.InvalidURL, httpx.UnsupportedProtocol) as exc:
            raise ProviderError(
                ProviderErrorCategory.CONFIGURATION,
                "Ollama URL configuration is invalid",
                provider_id=self.provider_id,
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            ) from exc
        except httpx.TransportError as exc:
            raise ProviderError(
                ProviderErrorCategory.TRANSIENT_NETWORK,
                f"Ollama service is unavailable ({type(exc).__name__})",
                provider_id=self.provider_id,
                attempt_outcome=_classify_transport_attempt_outcome(exc),
            ) from exc
        except Exception as exc:
            raise ProviderError(
                ProviderErrorCategory.UNKNOWN,
                f"Ollama request failed ({type(exc).__name__})",
                provider_id=self.provider_id,
            ) from exc

        if response.status_code < 200 or 300 <= response.status_code < 400:
            # Never turn a redirect/informational JSON body into a successful
            # generation. check_available() separately proves no POST was sent.
            raise ProviderError(
                ProviderErrorCategory.UNKNOWN,
                f"Ollama returned a non-success response ({response.status_code})",
                provider_id=self.provider_id,
                status_code=response.status_code,
                attempt_outcome=ProviderAttemptOutcome.UNKNOWN,
            )

        if response.status_code >= 400:
            detail, provider_code = _error_details(response)
            model_not_found = (
                response.status_code in (400, 404)
                and (
                    str(provider_code or "").lower() == "model_not_found"
                    or "model not found" in detail.lower()
                )
            )
            if model_not_found:
                category = ProviderErrorCategory.CONFIGURATION
            else:
                category = _classify_http_error(
                    response.status_code,
                    detail,
                    provider_code,
                    response.headers.get("Retry-After"),
                )
            raise ProviderError(
                category,
                f"Ollama error ({response.status_code}): {detail[:400]}",
                provider_id=self.provider_id,
                status_code=response.status_code,
                provider_code=provider_code,
                attempt_outcome=(
                    ProviderAttemptOutcome.REJECTED
                    if model_not_found
                    else _classify_http_attempt_outcome(
                        response.status_code, detail, provider_code
                    )
                ),
            )

        return response

    async def check_available(self) -> None:
        if not self.model:
            raise ProviderError(
                ProviderErrorCategory.CONFIGURATION,
                "OLLAMA_MODEL is not configured",
                provider_id=self.provider_id,
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            )

        try:
            response = await self._request("GET", "/api/tags")
        except ProviderError as exc:
            # The model check happens before /api/chat is dispatched.
            raise ProviderError(
                exc.category,
                str(exc),
                provider_id=exc.provider_id,
                status_code=exc.status_code,
                provider_code=exc.provider_code,
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            ) from exc
        try:
            data = response.json()
            models = data["models"]
            if not isinstance(models, list):
                raise TypeError("models must be a list")
        except (ValueError, KeyError, TypeError):
            raise ProviderError(
                ProviderErrorCategory.UNKNOWN,
                "Ollama returned an unexpected model-list response",
                provider_id=self.provider_id,
                status_code=response.status_code,
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            ) from None

        installed_names = {
            name
            for item in models
            if isinstance(item, dict)
            for name in (item.get("name"), item.get("model"))
            if isinstance(name, str)
        }
        if self.model not in installed_names:
            raise ProviderError(
                ProviderErrorCategory.CONFIGURATION,
                f"Configured Ollama model '{self.model}' is not installed",
                provider_id=self.provider_id,
                status_code=response.status_code,
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            )

    async def generate(self, messages: list[dict[str, str]]) -> GenerationResult:
        try:
            await self.check_available()
        except ProviderError as exc:
            raise ProviderError(
                exc.category,
                str(exc),
                provider_id=exc.provider_id,
                status_code=exc.status_code,
                provider_code=exc.provider_code,
                attempt_outcome=ProviderAttemptOutcome.NOT_SENT,
            ) from exc
        source_labels = self._document_source_labels(messages)
        options = {"num_gpu": self.num_gpu}
        request = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": options,
        }
        if source_labels is not None:
            options.update({
                "temperature": self._DOCUMENT_TEMPERATURE,
                "num_predict": self._DOCUMENT_OUTPUT_TOKENS,
            })
            request["format"] = self._document_response_schema(source_labels)
        response = await self._request(
            "POST",
            "/api/chat",
            json=request,
        )
        try:
            data = response.json()
            answer = data["message"]["content"]
        except (ValueError, KeyError, TypeError):
            raise ProviderError(
                ProviderErrorCategory.UNKNOWN,
                "Ollama returned an unexpected chat response",
                provider_id=self.provider_id,
                status_code=response.status_code,
            ) from None

        if source_labels is not None and isinstance(answer, str):
            answer = self._render_document_response(answer, source_labels)
        if not isinstance(answer, str) or not answer.strip():
            raise ProviderError(
                ProviderErrorCategory.UNKNOWN,
                "Ollama returned an empty response",
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

    @staticmethod
    def _document_source_labels(messages: list[dict[str, str]]) -> tuple[str, ...] | None:
        if (type(messages) is not list or len(messages) != 2
                or type(messages[0]) is not dict or type(messages[1]) is not dict
                or messages[0].get("role") != "system"
                or messages[1].get("role") != "user"
                or type(messages[1].get("content")) is not str):
            return None
        try:
            payload = json.loads(messages[1]["content"])
        except (KeyError, TypeError, json.JSONDecodeError):
            return None
        if type(payload) is not dict:
            return None
        excerpts = payload.get("excerpts")
        if (set(payload) != {"question", "excerpts"} or type(payload.get("question")) is not str
                or type(excerpts) is not list or not 1 <= len(excerpts) <= 8):
            return None
        labels = tuple(f"D{index}" for index in range(1, len(excerpts) + 1))
        if not all(
            type(item) is list and len(item) == 2
            and type(item[0]) is str and item[0] == labels[index - 1]
            and type(item[1]) is str
            for index, item in enumerate(excerpts, start=1)
        ):
            return None
        return labels

    @staticmethod
    def _document_response_schema(source_labels: tuple[str, ...]) -> dict:
        return {
            "type": "object",
            "properties": {
                "sentences": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 16,
                    "items": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string", "minLength": 1, "maxLength": 2000},
                            "sources": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": len(source_labels),
                                "items": {"type": "string", "enum": list(source_labels)},
                                "uniqueItems": True,
                            },
                        },
                        "required": ["text", "sources"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["sentences"],
            "additionalProperties": False,
        }

    @staticmethod
    def _render_document_response(answer: str, source_labels: tuple[str, ...]) -> str:
        try:
            payload = json.loads(answer)
        except json.JSONDecodeError:
            return OllamaProvider._UNCONFIRMED_DOCUMENT_ANSWER
        if type(payload) is not dict or set(payload) != {"sentences"}:
            return OllamaProvider._UNCONFIRMED_DOCUMENT_ANSWER
        sentences = payload["sentences"]
        if type(sentences) is not list or not 1 <= len(sentences) <= 16:
            return OllamaProvider._UNCONFIRMED_DOCUMENT_ANSWER
        rendered = []
        for item in sentences:
            if (type(item) is not dict or set(item) != {"text", "sources"}
                    or type(item["text"]) is not str or not item["text"].strip()
                    or len(item["text"]) > 2000 or type(item["sources"]) is not list
                    or not 1 <= len(item["sources"]) <= len(source_labels)
                    or any(type(label) is not str or label not in source_labels for label in item["sources"])
                    or len(set(item["sources"])) != len(item["sources"])):
                return OllamaProvider._UNCONFIRMED_DOCUMENT_ANSWER
            text = item["text"].strip()
            references = " ".join(f"[{label}]" for label in item["sources"])
            rendered.append(f"{text} {references}".rstrip())
        return " ".join(rendered)

    async def reply(self, messages: list[dict[str, str]]) -> str:
        """Legacy string-returning API retained for existing callers."""
        return (await self.generate(messages)).text
