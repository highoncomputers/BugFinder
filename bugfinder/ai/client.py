from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

from bugfinder.core.config import settings
from bugfinder.core.exceptions import AIClientError

logger = logging.getLogger(__name__)


class AIProviderError(AIClientError):
    pass


class BaseAIProvider:
    def __init__(self, api_key: str, model: str, base_url: str):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    async def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError

    async def chat_text(self, system_prompt: str | None = None, user_prompt: str = "", **kwargs: Any) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        result = await self.chat(messages, **kwargs)
        return result.get("choices", [{}])[0].get("message", {}).get("content", "")

    async def chat_json(self, system_prompt: str | None = None, user_prompt: str = "", **kwargs: Any) -> dict[str, Any]:
        text = await self.chat_text(system_prompt=system_prompt, user_prompt=user_prompt, **kwargs)
        try:
            start = text.index("{")
            end = text.rindex("}") + 1
            text = text[start:end]
            return json.loads(text)
        except (json.JSONDecodeError, ValueError) as e:
            raise AIProviderError(f"Failed to parse JSON response: {e}") from e

    async def is_available(self) -> bool:
        return bool(self.api_key)


class NVIDIAProvider(BaseAIProvider):
    async def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        if not self.api_key:
            raise AIProviderError("NVIDIA API key not configured. Set BF_NVIDIA_API_KEY.")

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", settings.ai_temperature),
            "max_tokens": kwargs.get("max_tokens", settings.ai_max_tokens),
        }
        if kwargs.get("response_format"):
            payload["response_format"] = kwargs["response_format"]

        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(settings.request_timeout),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        ) as client:
            resp = await client.post("/chat/completions", json=payload)
            resp.raise_for_status()
            return resp.json()


class OpenAIProvider(BaseAIProvider):
    async def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        if not self.api_key:
            raise AIProviderError("OpenAI API key not configured. Set BF_OPENAI_API_KEY.")

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", settings.ai_temperature),
            "max_tokens": kwargs.get("max_tokens", settings.ai_max_tokens),
        }
        if kwargs.get("response_format"):
            payload["response_format"] = kwargs["response_format"]

        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(settings.request_timeout),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        ) as client:
            resp = await client.post("/chat/completions", json=payload)
            resp.raise_for_status()
            return resp.json()


class AnthropicProvider(BaseAIProvider):
    async def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        if not self.api_key:
            raise AIProviderError("Anthropic API key not configured. Set BF_ANTHROPIC_API_KEY.")

        system = ""
        clean_messages = []
        for m in messages:
            if m["role"] == "system":
                system = m["content"]
            else:
                clean_messages.append(m)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": clean_messages,
            "max_tokens": kwargs.get("max_tokens", settings.ai_max_tokens),
        }
        if system:
            payload["system"] = system

        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(settings.request_timeout),
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
        ) as client:
            resp = await client.post("/messages", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return {
                "choices": [{
                    "message": {
                        "content": data.get("content", [{}])[0].get("text", "") if isinstance(data.get("content"), list) else str(data.get("content", ""))
                    }
                }]
            }


class OllamaProvider(BaseAIProvider):
    async def chat(self, messages: list[dict[str, str]], **kwargs: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }

        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(settings.request_timeout),
        ) as client:
            resp = await client.post("/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return {
                "choices": [{
                    "message": {"content": data.get("message", {}).get("content", "")}
                }]
            }


def get_ai_client() -> Optional[BaseAIProvider]:
    provider = settings.ai_provider.lower()
    if provider == "nvidia":
        if settings.nvidia_api_key:
            return NVIDIAProvider(settings.nvidia_api_key, settings.nvidia_model, settings.nvidia_base_url)
    elif provider == "openai":
        from bugfinder.core.config import Settings
        cfg = Settings()
        api_key = getattr(cfg, "openai_api_key", "") or getattr(settings, "openai_api_key", "")
        model = getattr(cfg, "openai_model", "gpt-4o") or getattr(settings, "openai_model", "gpt-4o")
        base_url = getattr(cfg, "openai_base_url", "https://api.openai.com/v1")
        if api_key:
            return OpenAIProvider(api_key, model, base_url)
    elif provider == "anthropic":
        api_key = getattr(settings, "anthropic_api_key", "")
        model = getattr(settings, "anthropic_model", "claude-3-opus-20240229")
        base_url = getattr(settings, "anthropic_base_url", "https://api.anthropic.com")
        if api_key:
            return AnthropicProvider(api_key, model, base_url)
    elif provider == "ollama":
        base_url = getattr(settings, "ollama_base_url", "http://localhost:11434")
        model = getattr(settings, "ollama_model", "llama3")
        return OllamaProvider("", model, base_url)

    if settings.nvidia_api_key:
        return NVIDIAProvider(settings.nvidia_api_key, settings.nvidia_model, settings.nvidia_base_url)
    return None
