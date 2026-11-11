from typing import Protocol
import httpx

class ChatProvider(Protocol):
    async def reply(self, messages: list[dict[str, str]]) -> str: ...

class OpenAICompatibleProvider:
    def __init__(self, api_key: str, base_url: str, model: str, timeout: float = 45.0):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    async def reply(self, messages: list[dict[str, str]]) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload
            )

        if response.status_code >= 400:
            detail = "Provider rejected the request"
            try:
                detail = response.json().get("error", {}).get("message", detail)
            except (ValueError, AttributeError):
                pass
            raise RuntimeError(f"Provider error ({response.status_code}): {detail[:400]}")

        data = response.json()
        try:
            answer = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise RuntimeError("Provider returned an unexpected response format")

        if not isinstance(answer, str) or not answer.strip():
            raise RuntimeError("Provider returned an empty response")

        return answer.strip()
