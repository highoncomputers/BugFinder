from __future__ import annotations

import json
from typing import Any

import httpx

from bugfinder.core.config import settings
from bugfinder.core.exceptions import AIClientError


class NVIDIAError(AIClientError):
    pass


class NVIDIAClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.api_key = api_key or settings.nvidia_api_key
        self.model = model or settings.nvidia_model
        self.base_url = base_url or settings.nvidia_base_url
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> NVIDIAClient:
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(settings.request_timeout),
            headers=self._headers(),
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_format: dict | None = None,
    ) -> dict[str, Any]:
        if not self.api_key:
            msg = (
                "NVIDIA API key not configured. "
                "Set BF_NVIDIA_API_KEY or run `bf config nvidia.api_key YOUR_KEY`."
            )
            raise AIClientError(msg)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature or settings.ai_temperature,
            "max_tokens": max_tokens or settings.ai_max_tokens,
        }
        if response_format:
            payload["response_format"] = response_format

        client = self._client or httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(settings.request_timeout),
            headers=self._headers(),
        )
        try:
            response = await client.post("/chat/completions", json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise NVIDIAError(f"API error: {e.response.status_code} - {e.response.text}") from e
        except httpx.RequestError as e:
            raise NVIDIAError(f"Request failed: {e}") from e
        finally:
            if not self._client:
                await client.aclose()

    async def chat_text(
        self,
        system_prompt: str | None = None,
        user_prompt: str = "",
        **kwargs: Any,
    ) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        result = await self.chat(messages, **kwargs)
        return result["choices"][0]["message"]["content"]

    async def chat_json(
        self,
        system_prompt: str | None = None,
        user_prompt: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        text = await self.chat_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format={"type": "json_object"},
            **kwargs,
        )
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise NVIDIAError(f"Failed to parse JSON response: {e}") from e

    async def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(10),
                headers=self._headers(),
            ) as client:
                resp = await client.get("/models")
                return resp.status_code == 200
        except Exception:
            return False
